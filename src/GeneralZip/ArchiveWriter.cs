using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using GeneralZip.Abstractions;
using GeneralZip.Internal;

namespace GeneralZip;

/// <summary>
/// 归档写入门面。负责事件与进度；格式细节由 IArchiveWriter 实现。
/// Dispose 时自动 Finish（未显式 Finish 的情况下），确保 using 语法得到完整归档。
/// 本类型非线程安全。
/// </summary>
public sealed class ArchiveWriter : IDisposable, IAsyncDisposable
{
    private readonly IArchiveWriter _inner;
    private readonly ArchiveWriteOptions _options;
    private readonly ProgressAggregator _progress;
    private long _entriesStarted;
    private bool _finished;

    private ArchiveWriter(IArchiveWriter inner, ArchiveWriteOptions options)
    {
        _inner = inner;
        _options = options;
        _progress = new ProgressAggregator(ArchivePhase.Compressing, options.Progress, () => OverallProgress);
    }

    // ---------- 创建 ----------

    /// <summary>按扩展名选择格式，创建归档文件。</summary>
    /// <param name="archivePath">归档输出路径（扩展名决定格式，如 .zip/.tar.gz）。</param>
    /// <param name="configure">写入选项。</param>
    /// <param name="formatName">显式指定格式名；给定时忽略扩展名推断。</param>
    /// <param name="registry">自定义格式注册表。</param>
    public static ArchiveWriter CreateNew(
        string archivePath,
        Action<ArchiveWriteOptions>? configure = null,
        string? formatName = null,
        ArchiveFormatRegistry? registry = null)
    {
        if (archivePath == null) throw new ArgumentNullException(nameof(archivePath));

        var options = new ArchiveWriteOptions();
        configure?.Invoke(options);

        var reg = registry ?? ArchiveFormatRegistry.Default;
        var format = formatName != null
            ? reg.FindByName(formatName) ?? throw new UnsupportedFormatException($"未注册的格式：{formatName}")
            : reg.DetectByExtension(archivePath)
              ?? throw new UnsupportedFormatException(
                  $"无法从扩展名识别格式：{archivePath}。请用 formatName 显式指定，或注册自定义格式。");

        if (!format.Info.CanWrite)
        {
            throw new UnsupportedFormatException($"格式 {format.Info.Name} 不支持创建归档");
        }

        var dir = Path.GetDirectoryName(Path.GetFullPath(archivePath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var stream = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: false);
        try
        {
            var writer = OpenOnStreamCore(stream, format, options);
            writer._ownsStream = stream;
            return writer;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>写入到流。formatName 必填（流无法从扩展名推断）。</summary>
    public static ArchiveWriter CreateNew(
        Stream output,
        string formatName,
        Action<ArchiveWriteOptions>? configure = null,
        ArchiveFormatRegistry? registry = null)
    {
        if (output == null) throw new ArgumentNullException(nameof(output));
        if (formatName == null) throw new ArgumentNullException(nameof(formatName));

        var options = new ArchiveWriteOptions();
        configure?.Invoke(options);

        var reg = registry ?? ArchiveFormatRegistry.Default;
        var format = reg.FindByName(formatName)
                     ?? throw new UnsupportedFormatException($"未注册的格式：{formatName}");

        if (!format.Info.CanWrite)
        {
            throw new UnsupportedFormatException($"格式 {format.Info.Name} 不支持创建归档");
        }

        return OpenOnStreamCore(output, format, options);
    }

    private static ArchiveWriter OpenOnStreamCore(Stream stream, IArchiveFormat format, ArchiveWriteOptions options)
    {
        var effective = options.CloneForFormat();
        effective.EncryptionProvider = options.ResolveProvider(EncryptionRegistry.Default);
        var inner = format.OpenWrite(stream, effective);
        return new ArchiveWriter(inner, options);
    }

    // ---------- 实例 API ----------

    /// <summary>格式信息。</summary>
    public ArchiveFormatInfo Format => _inner.Info;

    private Stream? _ownsStream;

    public event EventHandler<EntryEventArgs>? EntryStarted;
    public event EventHandler<EntryProgressEventArgs>? EntryProgress;
    public event EventHandler<EntryEventArgs>? EntryCompleted;
    public event EventHandler<EntryFailedEventArgs>? EntryFailed;
    public event EventHandler<ArchiveProgress>? OverallProgress;

    /// <summary>添加文件。entryName 缺省为文件名。</summary>
    public void AddFile(string filePath, string? entryName = null)
    {
        using var content = OpenSourceFile(filePath, entryName, out var name, out var size, out var mtime);
        AddEntryCore(name, content, size, mtime, CancellationToken.None);
    }

    /// <summary>异步添加文件。</summary>
    public async Task AddFileAsync(string filePath, string? entryName = null, CancellationToken cancellationToken = default)
    {
        using var content = OpenSourceFile(filePath, entryName, out var name, out var size, out var mtime);
        await AddEntryCoreAsync(name, content, size, mtime, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// 递归添加目录。子目录结构映射为条目前缀；目录本身以占位条目记录（格式支持时）。
    /// </summary>
    /// <param name="directoryPath">源目录。</param>
    /// <param name="entryPrefix">条目前缀（如 "data"）；null 为根。</param>
    /// <param name="filter">文件路径过滤器；null = 全部。</param>
    public void AddDirectory(string directoryPath, string? entryPrefix = null, Predicate<string>? filter = null)
        => AddDirectoryCore(directoryPath, entryPrefix, filter, async: false, CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>异步递归添加目录。</summary>
    public Task AddDirectoryAsync(string directoryPath, string? entryPrefix = null, Predicate<string>? filter = null, CancellationToken cancellationToken = default)
        => AddDirectoryCore(directoryPath, entryPrefix, filter, async: true, cancellationToken);

    /// <summary>添加流内容为条目（size 已知时进度更准确）。</summary>
    public void AddStream(string entryName, Stream content, long? size = null, DateTimeOffset? lastWriteTime = null)
    {
        if (entryName == null) throw new ArgumentNullException(nameof(entryName));
        if (content == null) throw new ArgumentNullException(nameof(content));
        AddEntryCore(entryName, content, size, lastWriteTime, CancellationToken.None);
    }

    /// <summary>完成归档（写中央目录/索引）。Dispose 未 Finish 时会自动调用。</summary>
    public void Finish(CancellationToken cancellationToken = default)
    {
        if (_finished) return;
        _finished = true;
        _progress.SwitchPhase(ArchivePhase.Finalizing);
        _inner.Finish(cancellationToken);
        _progress.Finalize();
    }

    /// <summary>异步完成归档。</summary>
    public Task FinishAsync(CancellationToken cancellationToken = default)
    {
        if (_finished) return Task.CompletedTask;
        _finished = true;
        _progress.SwitchPhase(ArchivePhase.Finalizing);
        var t = _inner.FinishAsync(cancellationToken);
        _progress.Finalize();
        return t;
    }

    // ---------- 内部 ----------

    private static FileStream OpenSourceFile(string filePath, string? entryName, out string name, out long size, out DateTimeOffset? mtime)
    {
        if (filePath == null) throw new ArgumentNullException(nameof(filePath));
        if (!File.Exists(filePath)) throw new FileNotFoundException("源文件不存在", filePath);

        var fi = new FileInfo(filePath);
        name = EntryPathResolver.NormalizeEntryName(entryName ?? fi.Name);
        size = fi.Length;
        mtime = fi.LastWriteTimeUtc;
        return new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
    }

    private async Task AddDirectoryCore(string directoryPath, string? entryPrefix, Predicate<string>? filter, bool async, CancellationToken ct)
    {
        if (directoryPath == null) throw new ArgumentNullException(nameof(directoryPath));
        if (!Directory.Exists(directoryPath)) throw new DirectoryNotFoundException($"源目录不存在：{directoryPath}");

        var root = Path.GetFullPath(directoryPath);
        var prefix = entryPrefix == null ? string.Empty : EntryPathResolver.NormalizeEntryName(entryPrefix).TrimEnd('/');
        if (prefix.Length > 0) prefix += "/";

        foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
        {
            ct.ThrowIfCancellationRequested();
            var rel = Path.GetFullPath(dir).Substring(root.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var entryDirName = prefix + EntryPathResolver.NormalizeEntryName(rel) + "/";
            _inner.AddDirectoryEntry(entryDirName, new ArchiveEntryMetadata { LastWriteTime = Directory.GetLastWriteTimeUtc(dir) });
        }

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            ct.ThrowIfCancellationRequested();
            if (filter != null && !filter(file)) continue;

            var rel = Path.GetFullPath(file).Substring(root.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var entryName = prefix + EntryPathResolver.NormalizeEntryName(rel);
            if (async)
            {
                await AddFileAsync(file, entryName, ct).ConfigureAwait(false);
            }
            else
            {
                AddFile(file, entryName);
            }
        }
    }

    private void AddEntryCore(string entryName, Stream content, long? size, DateTimeOffset? mtime, CancellationToken ct)
    {
        var meta = new ArchiveEntryMetadata
        {
            Size = size ?? -1,
            LastWriteTime = mtime ?? _options.DefaultLastWriteTime ?? DateTimeOffset.Now,
        };

        var relay = new Relay(this, entryName, size);
        RaiseEntryStarted(entryName, size);
        _progress.BeginEntry(entryName, size);
        _entriesStarted++;

        try
        {
            using var counted = new CountingStream(content, relay);
            _inner.AddEntry(entryName, counted, meta, ct);
            RaiseEntryCompleted(entryName);
            _progress.CompleteEntry(relay.Bytes);
        }
        catch (Exception ex)
        {
            RaiseEntryFailed(entryName, ex);
            throw;
        }
    }

    private async Task AddEntryCoreAsync(string entryName, Stream content, long? size, DateTimeOffset? mtime, CancellationToken ct)
    {
        var meta = new ArchiveEntryMetadata
        {
            Size = size ?? -1,
            LastWriteTime = mtime ?? _options.DefaultLastWriteTime ?? DateTimeOffset.Now,
        };

        var relay = new Relay(this, entryName, size);
        RaiseEntryStarted(entryName, size);
        _progress.BeginEntry(entryName, size);
        _entriesStarted++;

        try
        {
            using var counted = new CountingStream(content, relay);
            // 格式层 AddEntry 当前为同步管道（缓冲复制）；此处让出线程以保持异步签名语义
            await Task.Run(() => _inner.AddEntry(entryName, counted, meta, ct), ct).ConfigureAwait(false);
            RaiseEntryCompleted(entryName);
            _progress.CompleteEntry(relay.Bytes);
        }
        catch (Exception ex)
        {
            RaiseEntryFailed(entryName, ex);
            throw;
        }
    }

    private void RaiseEntryStarted(string name, long? size) =>
        EntryStarted?.Invoke(this, new EntryEventArgs(new EntryView(name, size)));

    private void RaiseEntryCompleted(string name) =>
        EntryCompleted?.Invoke(this, new EntryEventArgs(new EntryView(name, null)));

    private void RaiseEntryFailed(string name, Exception ex) =>
        EntryFailed?.Invoke(this, new EntryFailedEventArgs(new EntryView(name, null), ex));

    /// <summary>写入侧的轻量条目视图（源文件尚未进入归档，仅有名称与大小）。</summary>
    private sealed class EntryView : IArchiveEntry
    {
        public EntryView(string fullName, long? size)
        {
            FullName = fullName;
            Size = size ?? -1;
        }

        public string FullName { get; }
        public string Name
        {
            get
            {
                var idx = FullName.LastIndexOf('/');
                return idx >= 0 ? FullName.Substring(idx + 1) : FullName;
            }
        }

        public long Size { get; }
        public long CompressedSize => -1;
        public DateTimeOffset? LastWriteTime => null;
        public bool IsDirectory => FullName.EndsWith("/", StringComparison.Ordinal);
        public bool IsEncrypted => false;
        public string? EncryptionAlgorithm => null;
        public uint? Crc32 => null;
        public string? Comment => null;
    }

    private sealed class Relay
    {
        private readonly ArchiveWriter _owner;
        private readonly string _name;
        private readonly long? _size;
        private long _lastEventBytes;

        public Relay(ArchiveWriter owner, string name, long? size)
        {
            _owner = owner;
            _name = name;
            _size = size;
        }

        public long Bytes { get; private set; }

        public void Report(long delta)
        {
            if (delta <= 0) return;
            Bytes += delta;
            _owner._progress.ReportEntryBytes(delta);
            if (Bytes - _lastEventBytes >= 65536)
            {
                _lastEventBytes = Bytes;
                _owner.EntryProgress?.Invoke(_owner, new EntryProgressEventArgs(
                    new EntryView(_name, _size), Bytes, _size));
            }
        }
    }

    private sealed class CountingStream : Stream
    {
        private readonly Stream _inner;
        private readonly Relay _relay;

        public CountingStream(Stream inner, Relay relay)
        {
            _inner = inner;
            _relay = relay;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = _inner.Read(buffer, offset, count);
            if (n > 0) _relay.Report(n);
            return n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    public void Dispose()
    {
        if (!_finished)
        {
            try
            {
                Finish(CancellationToken.None);
            }
            catch
            {
                // Dispose 内自动收尾失败不吞掉用户显式 Finish 的异常路径；此处保持静默以不遮蔽主异常
            }
        }

        _inner.Dispose();
        _ownsStream?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (!_finished)
        {
            try
            {
                await FinishAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // 同步 Dispose 的理由
            }
        }

        _inner.Dispose();
        _ownsStream?.Dispose();
    }
}
