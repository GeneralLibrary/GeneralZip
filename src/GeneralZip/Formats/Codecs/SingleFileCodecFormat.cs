using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Formats.Codecs;

/// <summary>
/// 单文件编解码格式基类（GZ / BZ2 / XZ / Zstd / LZ4 / BROTLI）。
/// 语义：整包 = 一个条目（原始文件内容的压缩流）。
/// 托管实现（GZIP）为真流式；原生实现经 Rust 核心的回调式转码：
/// 压缩直通落盘（零临时文件），解压整段解码到单个临时文件后惰性读取。
/// </summary>
public abstract class SingleFileCodecFormat : IArchiveFormat
{
    private readonly string _name;
    private readonly string[] _extensions;
    private readonly string? _description;
    private readonly FormatCapabilities _capabilities;

    protected SingleFileCodecFormat(string name, string[] extensions, string? description, bool supportsWrite)
    {
        _name = name;
        _extensions = extensions;
        _description = description;
        _capabilities = FormatCapabilities.Read | FormatCapabilities.SeekableRead
                        | (supportsWrite ? FormatCapabilities.Write : FormatCapabilities.None);
    }

    public ArchiveFormatInfo Info => new(_name, _extensions, _capabilities, _description);

    /// <summary>解压包装（托管路径；原生格式走 <see cref="NativeCodecId"/> 路径）。</summary>
    protected abstract Stream OpenDecompress(Stream source);

    /// <summary>压缩包装（托管路径；CodecWriter 对原生格式不走此处）。</summary>
    protected abstract Stream OpenCompress(Stream destination);

    /// <summary>签名检查（前部字节）。</summary>
    protected abstract bool MatchesPrefix(byte[] prefix, int length);

    /// <summary>原生编解码器标识（Rust 核心中的 codec id）；null = 托管实现（GZIP）。</summary>
    protected virtual string? NativeCodecId => null;

    /// <summary>是否为原生转码格式（写入直通、读取经临时解码）。</summary>
    internal bool IsNativeTranscoder => NativeCodecId != null;

    internal string? CodecId => NativeCodecId;

    internal Stream CreateCompressor(Stream destination) => OpenCompress(destination);

    public bool MatchesSignature(Stream stream)
    {
        long restorePos = -1;
        if (stream.CanSeek) restorePos = stream.Position;

        try
        {
            var prefix = new byte[16];
            var total = 0;
            while (total < prefix.Length)
            {
                var n = stream.Read(prefix, total, prefix.Length - total);
                if (n <= 0) break;
                total += n;
            }

            return MatchesPrefix(prefix, total);
        }
        finally
        {
            if (restorePos >= 0) stream.Position = restorePos;
        }
    }

    public bool MatchesExtension(string extension)
    {
        foreach (var ext in _extensions)
        {
            if (extension.Equals(ext, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        var entryName = DeriveEntryName(options.SourceName);
        return new CodecReader(OpenDecompress(stream), Info, entryName, ownsInner: true);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
    {
        return new CodecWriter(stream, Info, this);
    }

    /// <summary>从源文件名推导条目名（剥掉压缩扩展名）。</summary>
    internal string DeriveEntryName(string? sourceName)
    {
        if (string.IsNullOrEmpty(sourceName)) return "content";

        var name = System.IO.Path.GetFileName(sourceName);
        foreach (var ext in _extensions)
        {
            if (name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
            {
                return name.Substring(0, name.Length - ext.Length);
            }
        }

        return name;
    }

    internal void EnsureWritable()
    {
        if ((_capabilities & FormatCapabilities.Write) == 0)
        {
            throw new NotSupportedException($"Format {_name} does not support writing in its current configuration");
        }
    }
}

/// <summary>单文件编解码读取器（单条目）。</summary>
internal sealed class CodecReader : IArchiveReader
{
    private readonly Stream _decompressed;
    private readonly bool _ownsInner;

    public CodecReader(Stream decompressed, ArchiveFormatInfo info, string entryName, bool ownsInner)
    {
        _decompressed = decompressed;
        Format = info;
        _ownsInner = ownsInner;
        var entry = new CodecEntry(entryName, decompressed is { CanSeek: true } s ? s.Length : -1);
        Entries = new IArchiveEntry[] { entry };
    }

    public ArchiveFormatInfo Format { get; }

    public IReadOnlyList<IArchiveEntry> Entries { get; }

    public bool IsEncrypted => false;

    public Stream OpenEntryStream(IArchiveEntry entry)
    {
        if (Entries.Count == 0 || !ReferenceEquals(Entries[0], entry))
        {
            throw new ArgumentException("Entry does not belong to this archive", nameof(entry));
        }

        return _decompressed;
    }

    public void CopyEntryTo(IArchiveEntry entry, Stream destination, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        int read;
        while ((read = _decompressed.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            destination.Write(buffer, 0, read);
        }
    }

    public void Dispose()
    {
        if (_ownsInner) _decompressed.Dispose();
    }
}

/// <summary>单文件编解码条目视图。</summary>
internal sealed class CodecEntry : IArchiveEntry
{
    public CodecEntry(string fullName, long decompressedLength)
    {
        FullName = fullName;
        Size = decompressedLength;
    }

    public string FullName { get; }
    public string Name => FullName;
    public long Size { get; }
    public long CompressedSize => -1;
    public DateTimeOffset? LastWriteTime => null;
    public bool IsDirectory => false;
    public bool IsEncrypted => false;
    public string? EncryptionAlgorithm => null;
    public uint? Crc32 => null;
    public string? Comment => null;
}

/// <summary>
/// 单文件编解码写入器（仅接受一个条目）。
/// 原生转码格式：条目内容经 Rust 核心流式压缩直通落盘；托管格式（GZIP）经压缩流包装。
/// </summary>
internal sealed class CodecWriter : IArchiveWriter
{
    private readonly Stream _destination;      // 最终输出流（不属于本对象）
    private readonly Stream? _compressWrap;    // 托管（GZIP）路径的压缩包装
    private readonly SingleFileCodecFormat _owner;
    private readonly ArchiveWriteOptions _options;
    private bool _finished;
    private bool _entryAdded;

    public CodecWriter(Stream destination, ArchiveFormatInfo info, SingleFileCodecFormat owner)
    {
        _destination = destination;
        Info = info;
        _owner = owner;
        _options = new ArchiveWriteOptions();
        _compressWrap = owner.IsNativeTranscoder ? null : owner.CreateCompressor(destination);
    }

    public ArchiveFormatInfo Info { get; }

    public ArchiveWriteOptions Options => _options;

    public void AddDirectoryEntry(string entryName, ArchiveEntryMetadata metadata)
    {
        // 单文件编解码格式无目录概念：忽略
    }

    public void AddEntry(string entryName, Stream content, ArchiveEntryMetadata metadata, CancellationToken cancellationToken)
    {
        _owner.EnsureWritable();
        if (_entryAdded)
        {
            throw new NotSupportedException($"Format {_owner.Info.Name} supports only one input entry");
        }

        _entryAdded = true;

        if (_owner.IsNativeTranscoder)
        {
            // 直通流式压缩：明文经回调拉入 Rust 核心，压缩字节直接落盘
            NativeCodecRouter.CompressStream(content, _destination, _owner.CodecId!, level: 6, cancellationToken);
            return;
        }

        var buffer = new byte[81920];
        int read;
        while ((read = content.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _compressWrap!.Write(buffer, 0, read);
        }
    }

    public void Finish(CancellationToken cancellationToken)
    {
        if (_finished) return;
        _finished = true;
        _compressWrap?.Flush();
        _destination.Flush();
    }

    public Task FinishAsync(CancellationToken cancellationToken)
    {
        Finish(cancellationToken);
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return default;
    }

    public void Dispose()
    {
        // 先收尾（Flush 输出），再 Dispose 压缩包装（gzip 在 Dispose 时写终结块；底层流不关闭）
        if (!_finished)
        {
            try { Finish(CancellationToken.None); } catch { /* 自动收尾失败不遮蔽主异常 */ }
        }

        _compressWrap?.Dispose();
    }
}
