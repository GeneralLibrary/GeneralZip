using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Native;

/// <summary>
/// 7z 格式提供者（经 Rust 原生核心）。读写均支持；加密为 7z 标准 AES-256。
/// </summary>
public sealed class SevenZipNativeFormat : IArchiveFormat
{
    internal SevenZipNativeFormat() { }

    public ArchiveFormatInfo Info { get; } = new(
        "7Z",
        new[] { ".7z" },
        FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.EncryptedRead |
        FormatCapabilities.EncryptedWrite | FormatCapabilities.SeekableRead,
        "7z (Rust native core: LZMA2 + AES-256)");

    public bool MatchesSignature(Stream stream)
    {
        long restore = -1;
        if (stream.CanSeek) restore = stream.Position;
        try
        {
            var arr = new byte[6];
            var total = 0;
            while (total < 6)
            {
                var n = stream.Read(arr, total, 6 - total);
                if (n <= 0) break;
                total += n;
            }

            return total >= 6
                && arr[0] == 0x37 && arr[1] == 0x7A && arr[2] == 0xBC
                && arr[3] == 0xAF && arr[4] == 0x27 && arr[5] == 0x1C;
        }
        finally
        {
            if (restore >= 0) stream.Position = restore;
        }
    }

    public bool MatchesExtension(string extension) =>
        extension.Equals(".7z", StringComparison.OrdinalIgnoreCase);

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        NativeCoreLoader.EnsureLoaded();
        return new SevenZipNativeReader(stream, options);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
    {
        NativeCoreLoader.EnsureLoaded();
        return new SevenZipNativeWriter(stream, options);
    }
}

/// <summary>7z 读取器：列表经 gzp_7z_list_json；条目解压经 gzp_7z_extract（单条目到临时文件）。</summary>
internal sealed class SevenZipNativeReader : IArchiveReader
{
    private readonly Stream _stream;
    private readonly ArchiveOpenOptions _options;
    private readonly string? _tempPath;
    private List<NativeEntryView>? _entries;
    private List<IArchiveEntry>? _entryViews;

    public SevenZipNativeReader(Stream stream, ArchiveOpenOptions options)
    {
        _stream = stream;
        _options = options;
        _tempPath = ResolveTempSourcePath(stream);
        if (_tempPath == null)
        {
            throw new NotSupportedException("7z reading requires a seekable stream or a file-path source (the native core opens archives by path)");
        }
    }

    public ArchiveFormatInfo Format { get; } = new(
        "7Z", new[] { ".7z" },
        FormatCapabilities.Read | FormatCapabilities.EncryptedRead | FormatCapabilities.SeekableRead,
        "7z (native core)");

    public IReadOnlyList<IArchiveEntry> Entries => EnsureEntries();

    public bool IsEncrypted { get; private set; }

    private List<NativeEntryView> EnsureEntries()
    {
        if (_entries != null) return _entries;

        var password = PasswordResolver.Resolve(_options, null);
        var json = NativeCall.ListJson(rar: false, _tempPath!, password);
        _entries = NativeEntryView.Parse(json);
        IsEncrypted = false; // 内容级加密在解压时才暴露；头加密会在列表阶段失败并被上层处理
        return _entries;
    }

    internal static string ListJson(string path, byte[]? password)
    {
        return NativeCall.ListJson(rar: false, path, password);
    }

    public Stream OpenEntryStream(IArchiveEntry entry)
    {
        if (entry is not NativeEntryView view || !TryIndexOf(entry, out var index))
        {
            throw new ArgumentException("Entry does not belong to this archive", nameof(entry));
        }

        var password = PasswordResolver.Resolve(_options, entry.FullName);
        var tempFile = Path.Combine(Path.GetTempPath(), $"gzp-{Guid.NewGuid():N}.bin");

        var status = GzpNative.gzp_7z_extract(
            _tempPath!, password, password != null ? (uint)(password.Length - 1) : 0,
            index, tempFile, null, IntPtr.Zero);

        if (status != GzpNative.GzpOk)
        {
            TryDelete(tempFile);
            throw NativeCall.ToException(status, "7z entry extraction failed", entry.FullName);
        }

        return new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.Read, 65536,
            FileOptions.DeleteOnClose | FileOptions.SequentialScan);
    }

    public void CopyEntryTo(IArchiveEntry entry, Stream destination, CancellationToken cancellationToken)
    {
        using var source = OpenEntryStream(entry);
        var buffer = new byte[81920];
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            destination.Write(buffer, 0, read);
        }
    }

    private bool TryIndexOf(IArchiveEntry entry, out long index)
    {
        var entries = EnsureEntries();
        for (var i = 0; i < entries.Count; i++)
        {
            if (ReferenceEquals(entries[i], entry))
            {
                index = i;
                return true;
            }
        }

        index = -1;
        return false;
    }

    private static string? ResolveTempSourcePath(Stream stream)
    {
        if (stream is FileStream fs)
        {
            return fs.Name;
        }

        // 非文件流：落到临时文件（按路径打开的 FFI 设计所致；v1 的取舍）
        var temp = Path.Combine(Path.GetTempPath(), $"gzp-{Guid.NewGuid():N}.7z");
        try
        {
            using (var target = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                if (stream.CanSeek) stream.Position = 0;
                stream.CopyTo(target, 65536);
            }

            return temp;
        }
        catch
        {
            TryDelete(temp);
            return null;
        }
    }

    internal static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* 清理失败忽略 */ }
    }

    public void Dispose()
    {
        if (_tempPath != null && _tempPath.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
        {
            // 文件流来源不删；临时拷贝来源删除
            if (!(_stream is FileStream))
            {
                TryDelete(_tempPath);
            }
        }
    }
}

/// <summary>
/// 7z 写入器：条目暂存到镜像目录，Finish 时一次性压缩（Rust 核心 per-source 压缩）。
/// AddStream 的内容同样落暂存文件。
/// </summary>
internal sealed class SevenZipNativeWriter : IArchiveWriter
{
    private readonly Stream _output;
    private readonly ArchiveWriteOptions _options;
    private readonly string _stagingDir;
    private readonly List<string> _sources = new();
    private bool _finished;

    public SevenZipNativeWriter(Stream output, ArchiveWriteOptions options)
    {
        _output = output;
        _options = options;
        _stagingDir = Path.Combine(Path.GetTempPath(), $"gzp-stage-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stagingDir);
    }

    public ArchiveFormatInfo Info { get; } = new(
        "7Z", new[] { ".7z" },
        FormatCapabilities.Write | FormatCapabilities.EncryptedWrite | FormatCapabilities.SeekableRead,
        "7z (native core)");

    public ArchiveWriteOptions Options => _options;

    public void AddDirectoryEntry(string entryName, ArchiveEntryMetadata metadata)
    {
        var name = Normalize(entryName).TrimEnd('/');
        var dir = Path.Combine(_stagingDir, ToOsPath(name));
        Directory.CreateDirectory(dir);
        MarkSourceRoots(dir);
    }

    public void AddEntry(string entryName, Stream content, ArchiveEntryMetadata metadata, CancellationToken cancellationToken)
    {
        var name = Normalize(entryName);
        var osPath = ToOsPath(name);
        var target = Path.Combine(_stagingDir, osPath);
        var parent = Path.GetDirectoryName(target);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

        using (var file = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var buffer = new byte[81920];
            int read;
            while ((read = content.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                file.Write(buffer, 0, read);
            }
        }

        MarkSourceRoots(target);
    }

    public void Finish(CancellationToken cancellationToken)
    {
        if (_finished) return;
        _finished = true;

        if (_sources.Count == 0)
        {
            throw new InvalidOperationException("A 7z archive requires at least one entry");
        }

        // 原生核心按路径产出归档；为避免与门面持有的输出流争锁，先写临时文件再回拷
        var produced = Path.Combine(_stagingDir, "produced.7z");
        var sourcesJson = System.Text.Json.JsonSerializer.Serialize(_sources);
        var password = GzpNative.PasswordBytes(_options.Password);

        var status = GzpNative.gzp_7z_compress(sourcesJson, produced, password,
            password != null ? (uint)(password.Length - 1) : 0, null, IntPtr.Zero);
        if (status != GzpNative.GzpOk)
        {
            throw NativeCall.ToException(status, "7z compression failed");
        }

        try
        {
            if (_output.CanSeek)
            {
                _output.Position = 0;
            }

            using var producedStream = File.OpenRead(produced);
            producedStream.CopyTo(_output, 65536);
            if (_output.CanSeek)
            {
                _output.SetLength(producedStream.Length);
            }

            _output.Flush();
        }
        finally
        {
            try { File.Delete(produced); } catch { /* 清理失败忽略 */ }
        }
    }

    public Task FinishAsync(CancellationToken cancellationToken)
    {
        Finish(cancellationToken);
        return Task.CompletedTask;
    }

    private void MarkSourceRoots(string addedPath)
    {
        // 一级条目作为压缩源（相对名由核心按 source 末段推导，与暂存目录结构一致）
        var relative = addedPath.Substring(_stagingDir.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = relative.Split(new[] { '/', '\\' }, 2)[0];
        var source = Path.Combine(_stagingDir, root);
        if (!_sources.Contains(source, StringComparer.OrdinalIgnoreCase))
        {
            _sources.Add(source);
        }
    }

    private static string Normalize(string name)
    {
        var n = name.Replace('\\', '/').TrimStart('/');
        while (n.Contains("//")) n = n.Replace("//", "/");
        if (n.Length == 0) throw new ArgumentException("Entry name is empty");
        return n;
    }

    private static string ToOsPath(string entryName) => entryName.Replace('/', Path.DirectorySeparatorChar);

    public ValueTask DisposeAsync()
    {
        Dispose();
        return default;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_stagingDir))
            {
                Directory.Delete(_stagingDir, recursive: true);
            }
        }
        catch
        {
            // 暂存清理失败忽略
        }
    }
}
