using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using GeneralZip.Abstractions;
using GeneralZip.Internal;

namespace GeneralZip;

/// <summary>
/// 归档读取门面。格式探测 → 格式级读取器 → 事件/策略编排的唯一入口。
/// 事件：EntryStarted / EntryProgress / EntryCompleted / EntryFailed /
///       OverallProgress / PasswordRequired / OverwriteQuery / ErrorReport。
/// 本类型非线程安全；不同实例可并发。
/// </summary>
public sealed class ArchiveReader : IDisposable
{
    private IArchiveReader _inner;
    private FileStream? _ownedStream; // set when opened by path; closed on Dispose
    private readonly ArchiveOpenOptions _options;
    private readonly PasswordGate _passwords;
    private EventHandler<PasswordRequiredEventArgs>? _passwordRequired;

    private ArchiveReader(ArchiveOpenOptions options)
    {
        _inner = new NullInner();
        _options = options;
        _passwords = new PasswordGate(options, () => _passwordRequired);
    }

    // ---------- 打开 ----------

    /// <summary>
    /// 打开归档文件（魔数自动探测格式，扩展名兜底）。
    /// </summary>
    /// <param name="path">归档路径。</param>
    /// <param name="configure">打开选项。</param>
    /// <param name="initialize">
    /// 订阅事件的钩子，在格式解析前执行——整包加密格式（7z 头部加密等）在 Open 期间就可能触发
    /// <see cref="PasswordRequired"/>，请在钩子中完成事件订阅。
    /// </param>
    /// <param name="registry">自定义格式注册表；null 用 <see cref="ArchiveFormatRegistry.Default"/>。</param>
    public static ArchiveReader Open(
        string path,
        Action<ArchiveOpenOptions>? configure = null,
        Action<ArchiveReader>? initialize = null,
        ArchiveFormatRegistry? registry = null)
    {
        if (path == null) throw new ArgumentNullException(nameof(path));

        var options = new ArchiveOpenOptions();
        configure?.Invoke(options);
        options.SourceName = System.IO.Path.GetFileName(path);

        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
        ArchiveReader? reader = null;
        try
        {
            reader = new ArchiveReader(options);
            AttachCore(reader, stream, options, initialize, registry, path, formatName: null);
            // Opening by path: the reader owns the FileStream. Format readers are created
            // with ownsStream:false, so the facade must close the stream on Dispose.
            reader._ownedStream = stream;
            return reader;
        }
        catch
        {
            reader?.Dispose();
            stream.Dispose();
            throw;
        }
    }

    /// <summary>从流打开归档。formatName 给定时跳过签名探测。</summary>
    public static ArchiveReader Open(
        Stream stream,
        string? formatName = null,
        Action<ArchiveOpenOptions>? configure = null,
        Action<ArchiveReader>? initialize = null,
        ArchiveFormatRegistry? registry = null)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        var options = new ArchiveOpenOptions();
        configure?.Invoke(options);
        var reader = new ArchiveReader(options);
        AttachCore(reader, stream, options, initialize, registry, sourcePath: null, formatName);
        return reader;
    }

    /// <summary>异步打开（内部为同步 IO；签名与异步 API 风格保持一致便于调用方切换）。</summary>
    public static Task<ArchiveReader> OpenAsync(
        string path,
        Action<ArchiveOpenOptions>? configure = null,
        Action<ArchiveReader>? initialize = null,
        ArchiveFormatRegistry? registry = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Open(path, configure, initialize, registry));
    }

    private static void AttachCore(
        ArchiveReader reader,
        Stream stream,
        ArchiveOpenOptions options,
        Action<ArchiveReader>? initialize,
        ArchiveFormatRegistry? registry,
        string? sourcePath,
        string? formatName)
    {
        var reg = registry ?? ArchiveFormatRegistry.Default;

        IArchiveFormat format;
        if (formatName != null)
        {
            format = reg.FindByName(formatName)
                     ?? throw new UnsupportedFormatException($"Unregistered format: {formatName}");
        }
        else
        {
            format = reg.Detect(stream.CanSeek ? stream : new ReadAheadProbeStream(stream));

            // 扩展名与魔数仲裁：外层压缩容器（BZ2/GZ 等）与 TAR 包装格式共享同一魔数，
            // 文件名含 ".tar." 时以扩展名匹配的 TAR 包装格式为准。
            var byExtension = sourcePath != null ? reg.DetectByExtension(sourcePath) : null;
            if (byExtension != null && format != null
                && !string.Equals(format.Info.Name, byExtension.Info.Name, StringComparison.OrdinalIgnoreCase)
                && sourcePath.IndexOf(".tar.", StringComparison.OrdinalIgnoreCase) >= 0
                && byExtension.Info.Name.StartsWith("TAR.", StringComparison.OrdinalIgnoreCase))
            {
                format = byExtension;
            }

            if (format == null)
            {
                if (sourcePath != null)
                {
                    format = reg.DetectByExtension(sourcePath);
                }

                if (format == null)
                {
                    throw new UnsupportedFormatException(
                        $"Unrecognized archive format{(sourcePath != null ? $": {sourcePath}" : string.Empty)}. " +
                        "Register a custom format via ArchiveFormatRegistry, or specify one explicitly with Open(stream, formatName).");
                }
            }
        }

        if (!format.Info.CanRead)
        {
            throw new UnsupportedFormatException($"Format {format.Info.Name} does not support reading");
        }

        if (stream.CanSeek)
        {
            stream.Position = 0;
        }

        initialize?.Invoke(reader);

        var inner = format.OpenRead(stream, reader.EffectiveOpenOptions());
        reader.Attach(inner);
    }

    /// <summary>把预置口令替换为闸门后的生效选项（格式层只见 IPasswordProvider）。</summary>
    internal ArchiveOpenOptions EffectiveOpenOptions() => new()
    {
        Password = null,
        PasswordProvider = _passwords,
        MaxPasswordAttempts = _options.MaxPasswordAttempts,
        EntryNameEncoding = _options.EntryNameEncoding,
        Progress = _options.Progress,
        SourceName = _options.SourceName,
    };

    private void Attach(IArchiveReader inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    // ---------- 实例 API ----------

    /// <summary>格式信息。</summary>
    public ArchiveFormatInfo Format => _inner.Format;

    /// <summary>归档内全部条目。</summary>
    public IReadOnlyList<IArchiveEntry> Entries => _inner.Entries;

    /// <summary>归档是否包含加密内容。</summary>
    public bool IsEncrypted => _inner.IsEncrypted;

    /// <summary>打开后补充的口令（优先级低于事件应答；下次询问生效）。</summary>
    public string? Password { get; set; }

    public event EventHandler<EntryEventArgs>? EntryStarted;
    public event EventHandler<EntryProgressEventArgs>? EntryProgress;
    public event EventHandler<EntryEventArgs>? EntryCompleted;
    public event EventHandler<EntryFailedEventArgs>? EntryFailed;
    public event EventHandler<ArchiveProgress>? OverallProgress;

    /// <summary>口令请求。整包加密格式请在 Open 的 initialize 钩子中订阅本事件。</summary>
    public event EventHandler<PasswordRequiredEventArgs>? PasswordRequired
    {
        add => _passwordRequired += value;
        remove => _passwordRequired -= value;
    }

    /// <summary>解压目标已存在时的询问（OverwritePolicy.Ask）。</summary>
    public event EventHandler<OverwriteQueryEventArgs>? OverwriteQuery;

    /// <summary>条目级错误上报（ErrorPolicy.RaiseEvent）。</summary>
    public event EventHandler<ArchiveErrorEventArgs>? ErrorReport;

    /// <summary>打开条目的解压流（解密+解压在流上顺序完成）。口令按预置/事件自动协商。</summary>
    public Stream OpenEntryStream(IArchiveEntry entry)
    {
        if (entry == null) throw new ArgumentNullException(nameof(entry));
        EnsureAttached();
        if (Password != null)
        {
            _passwords.SupplyOverride(entry.FullName, Password);
        }

        return _inner.OpenEntryStream(entry);
    }

    /// <summary>解压到目录（保留条目内部结构）。</summary>
    public ArchiveResult ExtractToDirectory(
        string destinationDirectory,
        ExtractionOptions? options = null,
        CancellationToken cancellationToken = default)
        => ExtractCore(destinationDirectory, options, cancellationToken, testOnly: false);

    /// <summary>异步解压到目录（与同步版本同实现，签名对齐便于调用方切换）。</summary>
    public Task<ArchiveResult> ExtractToDirectoryAsync(
        string destinationDirectory,
        ExtractionOptions? options = null,
        CancellationToken cancellationToken = default)
        => Task.FromResult(ExtractCore(destinationDirectory, options, cancellationToken, testOnly: false));

    /// <summary>解压单个条目到指定文件路径。</summary>
    public ArchiveResult ExtractEntry(
        IArchiveEntry entry,
        string destinationFilePath,
        ExtractionOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (entry == null) throw new ArgumentNullException(nameof(entry));
        if (destinationFilePath == null) throw new ArgumentNullException(nameof(destinationFilePath));
        EnsureAttached();
        options ??= new ExtractionOptions();

        var result = ArchiveResult.Empty();
        var progress = new ProgressAggregator(ArchivePhase.Decompressing, _options.Progress, () => OverallProgress);
        progress.SetTotals(1, entry.Size >= 0 ? entry.Size : null);
        progress.BeginEntry(entry.FullName, entry.Size >= 0 ? entry.Size : null);
        RaiseEntryStarted(entry);

        var relay = new EntryProgressRelay(this, entry, progress);
        var dummy = 0;
        var outcome = ExtractOne(entry, destinationFilePath, options, cancellationToken, relay, progress, result, new List<FailedEntry>(), testOnly: false, ref dummy);
        progress.Finalize(entry.Size >= 0 ? entry.Size : relay.BytesProcessed);
        if (outcome == Outcome.Abort) result.Aborted = true;
        return result;
    }

    /// <summary>完整性测试：解压到空（校验 CRC/HMAC/结构），不落盘。</summary>
    public ArchiveResult TestAll(ExtractionOptions? options = null, CancellationToken cancellationToken = default)
        => ExtractCore(null, options, cancellationToken, testOnly: true);

    // ---------- 解压主循环 ----------

    private ArchiveResult ExtractCore(
        string? destinationDirectory,
        ExtractionOptions? options,
        CancellationToken cancellationToken,
        bool testOnly)
    {
        EnsureAttached();
        options ??= new ExtractionOptions();
        var result = ArchiveResult.Empty();
        var failures = new List<FailedEntry>();

        if (!testOnly)
        {
            Directory.CreateDirectory(destinationDirectory!);
        }

        long totalBytes = 0;
        var allKnown = true;
        foreach (var e in _inner.Entries)
        {
            if (e.Size < 0) { allKnown = false; break; }
            totalBytes += e.Size;
        }

        var progress = new ProgressAggregator(ArchivePhase.Decompressing, _options.Progress, () => OverallProgress);
        progress.SetTotals(_inner.Entries.Count, allKnown ? totalBytes : null);

        foreach (var entry in _inner.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (entry.IsDirectory)
            {
                if (!testOnly)
                {
                    var dir = EntryPathResolver.Resolve(destinationDirectory!, entry, flatten: options.Flatten);
                    if (dir != null) Directory.CreateDirectory(dir);
                }

                progress.CompleteEntry(0);
                continue;
            }

            if (options.Filter != null && !options.Filter(entry))
            {
                result.SkippedCount++;
                progress.CompleteEntry(Math.Max(0, entry.Size));
                continue;
            }

            RaiseEntryStarted(entry);
            progress.BeginEntry(entry.FullName, entry.Size >= 0 ? entry.Size : null);

            string? targetPath = null;
            if (!testOnly)
            {
                targetPath = EntryPathResolver.Resolve(destinationDirectory!, entry, flatten: options.Flatten);
                if (targetPath == null)
                {
                    var ex = new ArchiveException("Unsafe entry path (absolute path or path traversal); extraction denied", entry.FullName);
                    RaiseEntryFailed(entry, ex);
                    var retry = 0;
                    _ = HandleError(entry, ex, options, failures, progress, allowRetry: false, ref retry);
                    continue;
                }
            }

            var relay = new EntryProgressRelay(this, entry, progress);
            var retryCount = 0;
            var outcome = ExtractOne(entry, targetPath, options, cancellationToken, relay, progress, result, failures, testOnly, ref retryCount);
            if (outcome == Outcome.Abort)
            {
                result.Aborted = true;
                progress.Finalize();
                result.Failures = failures;
                return result;
            }
        }

        progress.Finalize();
        result.Failures = failures;
        return result;
    }

    private enum Outcome { Done, Abort }

    private Outcome ExtractOne(
        IArchiveEntry entry,
        string? targetPath,
        ExtractionOptions options,
        CancellationToken cancellationToken,
        EntryProgressRelay relay,
        ProgressAggregator progress,
        ArchiveResult result,
        List<FailedEntry> failures,
        bool testOnly,
        ref int retryCount)
    {
        while (true)
        {
            try
            {
                string? finalPath = null;
                if (!testOnly)
                {
                    var action = ResolveOverwrite(entry, targetPath!, options);
                    if (action == OverwriteAction.Skip)
                    {
                        result.SkippedCount++;
                        progress.CompleteEntry(Math.Max(0, entry.Size));
                        return Outcome.Done;
                    }

                    if (action == OverwriteAction.Abort)
                    {
                        RaiseEntryFailed(entry, new OperationCanceledException("Overwrite prompt chose abort"));
                        return Outcome.Abort;
                    }

                    finalPath = targetPath!;
                    if (action == OverwriteAction.Rename)
                    {
                        finalPath = EntryPathResolver.NextAvailableName(finalPath, options.MaxRenameAttempts);
                    }

                    var dir = Path.GetDirectoryName(finalPath);
                    if (!string.IsNullOrEmpty(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }
                }

                using (var source = _inner.OpenEntryStream(entry))
                {
                    if (testOnly)
                    {
                        Drain(source, options.BufferSize, relay, cancellationToken);
                    }
                    else
                    {
                        CopyToFile(source, finalPath!, options.BufferSize, relay, cancellationToken);
                    }
                }

                if (!testOnly && options.PreserveTimestamps && entry.LastWriteTime.HasValue)
                {
                    TrySetTimestamp(finalPath!, entry.LastWriteTime.Value);
                }

                RaiseEntryCompleted(entry);
                progress.CompleteEntry(entry.Size >= 0 ? entry.Size : relay.BytesProcessed);
                result.ProcessedCount++;
                return Outcome.Done;
            }
            catch (OperationCanceledException)
            {
                RaiseEntryFailed(entry, new OperationCanceledException("Operation canceled", cancellationToken));
                throw;
            }
            catch (InvalidPasswordException ex)
            {
                // 口令重询问是交互协议，独立于 ErrorPolicy：还有通道就作废缓存重试
                _passwords.Invalidate(entry.FullName);
                RaiseEntryFailed(entry, ex);
                if (_passwords.CanReask(entry.FullName))
                {
                    continue;
                }

                var disposition = HandleError(entry, ex, options, failures, progress, allowRetry: false, ref retryCount);
                if (disposition == Disposition.Continue) return Outcome.Done;
                if (disposition == Disposition.Abort) return Outcome.Abort;
            }
            catch (Exception ex)
            {
                RaiseEntryFailed(entry, ex);
                var disposition = HandleError(entry, ex, options, failures, progress, allowRetry: true, ref retryCount);
                if (disposition == Disposition.Continue) return Outcome.Done;
                if (disposition == Disposition.Abort) return Outcome.Abort;
            }
        }
    }

    private enum Disposition { Retry, Continue, Abort }

    private Disposition HandleError(
        IArchiveEntry entry,
        Exception exception,
        ExtractionOptions options,
        List<FailedEntry> failures,
        ProgressAggregator progress,
        bool allowRetry,
        ref int retryCount)
    {
        switch (options.ErrorPolicy)
        {
            case ErrorPolicy.Throw:
                throw exception;

            case ErrorPolicy.SkipAll:
                failures.Add(new FailedEntry(entry.FullName, exception));
                progress.CompleteEntry(0);
                return Disposition.Continue;

            case ErrorPolicy.RaiseEvent:
            default:
                if (!allowRetry || retryCount >= options.MaxRetryPerEntry)
                {
                    failures.Add(new FailedEntry(entry.FullName, exception));
                    progress.CompleteEntry(0);
                    return Disposition.Continue;
                }

                var args = new ArchiveErrorEventArgs(entry.FullName, exception, retryCount, options.MaxRetryPerEntry);
                if (!RaiseSafe(args, () => ErrorReport?.Invoke(this, args), options))
                {
                    failures.Add(new FailedEntry(entry.FullName, exception));
                    progress.CompleteEntry(0);
                    return Disposition.Continue;
                }

                switch (args.Action)
                {
                    case ErrorAction.Skip:
                        failures.Add(new FailedEntry(entry.FullName, exception));
                        progress.CompleteEntry(0);
                        return Disposition.Continue;
                    case ErrorAction.Abort:
                        return Disposition.Abort;
                    case ErrorAction.Retry:
                    default:
                        retryCount++;
                        return Disposition.Retry;
                }
        }
    }

    private OverwriteAction ResolveOverwrite(IArchiveEntry entry, string targetPath, ExtractionOptions options)
    {
        if (!File.Exists(targetPath))
        {
            return OverwriteAction.Overwrite; // 目标不存在 → 直接写
        }

        switch (options.OverwritePolicy)
        {
            case OverwritePolicy.Throw:
                throw new IOException($"Target file already exists: {targetPath}");
            case OverwritePolicy.Overwrite:
                return OverwriteAction.Overwrite;
            case OverwritePolicy.Skip:
                return OverwriteAction.Skip;
            case OverwritePolicy.Rename:
                return OverwriteAction.Rename;
            case OverwritePolicy.Ask:
            default:
                var args = new OverwriteQueryEventArgs(entry.FullName, targetPath, entry.Size, entry.LastWriteTime);
                if (!RaiseSafe(args, () => OverwriteQuery?.Invoke(this, args), options))
                {
                    return OverwriteAction.Skip;
                }

                return args.Action;
        }
    }

    private bool RaiseSafe<T>(T args, Action raise, ExtractionOptions options)
        where T : EventArgs
    {
        try
        {
            raise();
            return true;
        }
        catch (Exception)
        {
            if (options.PropagateEventExceptions) throw;
            return false;
        }
    }

    private void RaiseEntryStarted(IArchiveEntry entry) => EntryStarted?.Invoke(this, new EntryEventArgs(entry));

    private void RaiseEntryCompleted(IArchiveEntry entry) => EntryCompleted?.Invoke(this, new EntryEventArgs(entry));

    private void RaiseEntryFailed(IArchiveEntry entry, Exception ex) => EntryFailed?.Invoke(this, new EntryFailedEventArgs(entry, ex));

    // ---------- IO ----------

    private static void CopyToFile(Stream source, string targetPath, int bufferSize, EntryProgressRelay relay, CancellationToken ct)
    {
        using var target = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, useAsync: false);
        var buffer = new byte[bufferSize];
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            target.Write(buffer, 0, read);
            relay.Report(read);
        }
    }

    private static void Drain(Stream source, int bufferSize, EntryProgressRelay relay, CancellationToken ct)
    {
        var buffer = new byte[bufferSize];
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            relay.Report(read);
        }
    }

    private static void TrySetTimestamp(string path, DateTimeOffset time)
    {
        try
        {
            File.SetLastWriteTime(path, time.LocalDateTime);
        }
        catch (Exception)
        {
            // 时间戳设置失败不影响解压结果
        }
    }

    private void EnsureAttached()
    {
        if (_inner is NullInner)
        {
            throw new InvalidOperationException("Reader is not initialized yet");
        }
    }

    public void Dispose()
    {
        _inner.Dispose();
        _ownedStream?.Dispose();
        _ownedStream = null;
    }

    /// <summary>条目内字节进度中继：聚合器 + EntryProgress 事件。</summary>
    private sealed class EntryProgressRelay
    {
        private readonly ArchiveReader _owner;
        private readonly IArchiveEntry _entry;
        private readonly ProgressAggregator _aggregator;
        private long _bytes;
        private long _lastEventBytes;

        public EntryProgressRelay(ArchiveReader owner, IArchiveEntry entry, ProgressAggregator aggregator)
        {
            _owner = owner;
            _entry = entry;
            _aggregator = aggregator;
        }

        public long BytesProcessed => _bytes;

        public void Report(long delta)
        {
            if (delta <= 0) return;
            _bytes += delta;
            _aggregator.ReportEntryBytes(delta);
            if (_bytes - _lastEventBytes >= 65536)
            {
                _lastEventBytes = _bytes;
                _owner.EntryProgress?.Invoke(_owner, new EntryProgressEventArgs(
                    _entry, _bytes, _entry.Size >= 0 ? _entry.Size : null));
            }
        }
    }

    /// <summary>两段式初始化期间的占位内核。</summary>
    private sealed class NullInner : IArchiveReader
    {
        public ArchiveFormatInfo Format { get; } = new("NONE", Array.Empty<string>(), FormatCapabilities.None);

        public IReadOnlyList<IArchiveEntry> Entries { get; } = Array.Empty<IArchiveEntry>();

        public bool IsEncrypted => false;

        public Stream OpenEntryStream(IArchiveEntry entry) => throw new InvalidOperationException("Reader is not initialized yet");

        public void CopyEntryTo(IArchiveEntry entry, Stream destination, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Reader is not initialized yet");

        public void Dispose() { }
    }
}

/// <summary>非可寻址流的魔数探测包装：缓冲前部字节，探测后按序重放。</summary>
internal sealed class ReadAheadProbeStream : Stream
{
    private readonly Stream _inner;
    private readonly byte[] _prefix;
    private int _prefixPos;
    private bool _prefixDone;

    public ReadAheadProbeStream(Stream inner, int prefixSize = 64)
    {
        _inner = inner;
        _prefix = new byte[prefixSize];
        var total = 0;
        while (total < prefixSize)
        {
            var n = inner.Read(_prefix, total, prefixSize - total);
            if (n <= 0) break;
            total += n;
        }

        PrefixLength = total;
    }

    /// <summary>探测接口读取前部缓冲。</summary>
    public byte[] PrefixBuffer => _prefix;

    public int PrefixLength { get; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (!_prefixDone)
        {
            var fromPrefix = Math.Min(count, PrefixLength - _prefixPos);
            if (fromPrefix > 0)
            {
                Array.Copy(_prefix, _prefixPos, buffer, offset, fromPrefix);
                _prefixPos += fromPrefix;
                if (_prefixPos >= PrefixLength) _prefixDone = true;
                return fromPrefix;
            }

            _prefixDone = true;
        }

        return _inner.Read(buffer, offset, count);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
