using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using GeneralZip.Abstractions;
using GeneralZip.Cryptography;
using GeneralZip.Internal;

namespace GeneralZip.Formats.Zip;

/// <summary>
/// ZIP 写入器：顺序写入 + 数据描述符（支持不可寻址输出流）+ 加密挂接 + Zip64 中央目录。
/// </summary>
internal sealed class ZipWriter : IArchiveWriter
{
    private readonly Stream _output;
    private readonly bool _ownsStream;
    private readonly ArchiveWriteOptions _options;
    private readonly IEncryptionProvider? _encryption;
    private readonly bool _utf8Names;
    private readonly List<CentralRecord> _centrals = new();
    private readonly CountingOutput _counter;
    private bool _finished;

    public ZipWriter(Stream output, ArchiveWriteOptions options, bool ownsStream, EncryptionRegistry? encryption = null)
    {
        _output = output ?? throw new ArgumentNullException(nameof(output));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _ownsStream = ownsStream;
        _counter = new CountingOutput(output);
        _utf8Names = IsUtf8(options.EntryNameEncoding);

        if (!output.CanWrite)
        {
            throw new ArgumentException("Output stream must be writable", nameof(output));
        }

        var provider = options.ResolveProvider(encryption ?? EncryptionRegistry.Default);
        if (provider != null && provider.AlgorithmId == "ZipCrypto" && !options.AllowWeakZipCrypto)
        {
            throw new NotSupportedException(
                "ZipCrypto is weak encryption and writing is disabled by default. Set options.AllowWeakZipCrypto = true to enable it explicitly (legacy interop scenarios only).");
        }

        _encryption = provider;
    }

    public ArchiveFormatInfo Info { get; } = new(
        "ZIP",
        new[] { ".zip" },
        FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.EncryptedRead |
        FormatCapabilities.EncryptedWrite | FormatCapabilities.SeekableRead | FormatCapabilities.Append,
        "In-house ZIP engine: Store/Deflate/Zip64 + ZipCrypto/WinZip AES/SM4-GM");

    public ArchiveWriteOptions Options => _options;

    public void AddDirectoryEntry(string entryName, ArchiveEntryMetadata metadata)
    {
        var name = NormalizeName(entryName);
        if (!name.EndsWith("/", StringComparison.Ordinal))
        {
            name += "/";
        }

        ZipTime.ToDos(metadata.LastWriteTime ?? DateTimeOffset.Now, out var dosTime, out var dosDate);

        var offset = _counter.TotalBytes;
        WriteLocalHeader(name, ZipConstants.MethodStore, dosTime, dosDate, encryptionExtra: null, encrypted: false);
        WriteDescriptor(crc: 0, compSize: 0, uncompSize: 0);

        _centrals.Add(new CentralRecord(name, ZipConstants.MethodStore, dosTime, dosDate, 0, 0, 0, offset, metadata, null, null, isDirectory: true, isEncrypted: false));
    }

    public void AddEntry(string entryName, Stream content, ArchiveEntryMetadata metadata, CancellationToken cancellationToken)
    {
        if (entryName == null) throw new ArgumentNullException(nameof(entryName));
        if (content == null) throw new ArgumentNullException(nameof(content));

        var name = NormalizeName(entryName);
        var isEmpty = metadata.Size == 0 || (content.CanSeek && content.Length == 0);
        var isStore = _options.Level == CompressionLevelChoice.NoCompression || isEmpty;
        var method = (ushort)(isStore ? ZipConstants.MethodStore : ZipConstants.MethodDeflate);

        ZipTime.ToDos(metadata.LastWriteTime ?? DateTimeOffset.Now, out var dosTime, out var dosDate);

        // 加密计划（需要真实压缩方法与 DOS 时间）
        EntryEncryptionPlan? plan = null;
        if (_encryption != null)
        {
            plan = _encryption.PrepareWrite(new EncryptionWriteContext(
                _options.Password!, name, crc32: null, plainSize: metadata.Size, method, dosTime, _options.KdfIterations));
        }

        var offset = _counter.TotalBytes;
        WriteLocalHeader(
            name,
            plan != null && plan.ExtraFieldId != null ? (ushort)ZipConstants.MethodEncryptedMarker : method,
            dosTime,
            dosDate,
            plan?.ExtraFieldData,
            plan != null,
            plan?.ExtraFieldId);

        var crcStream = new Crc32Stream(content, leaveOpen: true);

        // 先 Mark 再构造加密流：工厂会把盐/校验值前缀写入，必须计入密文总长
        _counter.Mark();
        Stream pipeline = plan != null ? plan.EncryptionStreamFactory(_counter) : _counter;

        try
        {
            if (isStore)
            {
                CopyPlain(crcStream, pipeline, cancellationToken);
            }
            else
            {
                var deflate = new DeflateStream(pipeline, MapLevel(_options.Level), leaveOpen: true);
                try
                {
                    CopyPlain(crcStream, deflate, cancellationToken);
                }
                finally
                {
                    deflate.Dispose(); // 刷出 deflate 终结块
                }
            }
        }
        finally
        {
            // 加密流 Dispose 触发 MAC 尾部刷出（非加密时为直通包装）
            if (!ReferenceEquals(pipeline, _counter))
            {
                pipeline.Dispose();
            }
        }

        var compressedBytes = _counter.BytesSinceMark;
        var crc = crcStream.Crc;
        var uncompSize = crcStream.BytesPassed;

        WriteDescriptor(crc, compressedBytes, uncompSize);
        _centrals.Add(new CentralRecord(
            name,
            plan != null && plan.ExtraFieldId != null ? (ushort)ZipConstants.MethodEncryptedMarker : method,
            dosTime, dosDate, crc, compressedBytes, uncompSize, offset, metadata,
            plan?.ExtraFieldData, plan?.ExtraFieldId, isDirectory: false, isEncrypted: plan != null));
    }

    public void Finish(CancellationToken cancellationToken)
    {
        if (_finished) return;
        _finished = true;

        cancellationToken.ThrowIfCancellationRequested();

        long cdOffset = _counter.TotalBytes;
        foreach (var central in _centrals)
        {
            WriteCentralHeader(central);
        }

        long cdSize = _counter.TotalBytes - cdOffset;
        var useZip64 = cdOffset > uint.MaxValue || cdSize > uint.MaxValue || _centrals.Count > ushort.MaxValue;
        var entryCount = _centrals.Count;

        if (useZip64)
        {
            var zip64EocdOffset = _counter.TotalBytes;
            var record = new byte[56];
            Le.Put32(record, 0, ZipConstants.Zip64EndOfCentralDirectorySignature);
            Le.Put64(record, 4, 44);
            Le.Put16(record, 12, 45);
            Le.Put16(record, 14, 45);
            Le.Put32(record, 16, 0);
            Le.Put32(record, 20, 0);
            Le.Put64(record, 24, (ulong)entryCount);
            Le.Put64(record, 32, (ulong)entryCount);
            Le.Put64(record, 40, (ulong)cdSize);
            Le.Put64(record, 48, (ulong)cdOffset);
            _counter.Write(record, 0, record.Length);

            var locator = new byte[20];
            Le.Put32(locator, 0, ZipConstants.Zip64EndOfCentralDirectoryLocatorSignature);
            Le.Put32(locator, 4, 0);
            Le.Put64(locator, 8, (ulong)zip64EocdOffset);
            Le.Put32(locator, 16, 1);
            _counter.Write(locator, 0, locator.Length);
        }

        var comment = _options.ArchiveComment != null ? _options.EntryNameEncoding.GetBytes(_options.ArchiveComment) : Array.Empty<byte>();
        if (comment.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Archive comment exceeds the 64KB limit");
        }

        var eocd = new byte[22 + comment.Length];
        Le.Put32(eocd, 0, ZipConstants.EndOfCentralDirectorySignature);
        Le.Put16(eocd, 4, 0);
        Le.Put16(eocd, 6, 0);
        Le.Put16(eocd, 8, useZip64 ? ushort.MaxValue : (ushort)entryCount);
        Le.Put16(eocd, 10, useZip64 ? ushort.MaxValue : (ushort)entryCount);
        Le.Put32(eocd, 12, useZip64 ? uint.MaxValue : (uint)cdSize);
        Le.Put32(eocd, 16, useZip64 ? uint.MaxValue : (uint)cdOffset);
        Le.Put16(eocd, 20, (ushort)comment.Length);
        Buffer.BlockCopy(comment, 0, eocd, 22, comment.Length);
        _counter.Write(eocd, 0, eocd.Length);
        _output.Flush();
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

    // ---------- 内部 ----------

    private void WriteLocalHeader(string name, ushort method, uint dosTime, uint dosDate,
        byte[]? encryptionExtra, bool encrypted, ushort? extraFieldId = null)
    {
        var nameBytes = EncodeName(name);

        byte[]? extra = null;
        if (encryptionExtra != null)
        {
            if (extraFieldId == null)
            {
                throw new InvalidOperationException("Encryption plan is missing the extra field id");
            }

            extra = new byte[4 + encryptionExtra.Length];
            Le.Put16(extra, 0, extraFieldId.Value);
            Le.Put16(extra, 2, (ushort)encryptionExtra.Length);
            Buffer.BlockCopy(encryptionExtra, 0, extra, 4, encryptionExtra.Length);
        }

        var flags = (ushort)(ZipConstants.FlagDataDescriptor | (_utf8Names ? ZipConstants.FlagUtf8 : 0) | (encrypted ? ZipConstants.FlagEncrypted : 0));

        var header = new byte[30 + nameBytes.Length + (extra?.Length ?? 0)];
        Le.Put32(header, 0, ZipConstants.LocalHeaderSignature);
        Le.Put16(header, 4, 20);
        Le.Put16(header, 6, flags);
        Le.Put16(header, 8, method);
        Le.Put16(header, 10, (ushort)dosTime);
        Le.Put16(header, 12, (ushort)dosDate);
        Le.Put32(header, 14, 0); // descriptor 模式：头中置 0
        Le.Put32(header, 18, 0);
        Le.Put32(header, 22, 0);
        Le.Put16(header, 26, (ushort)nameBytes.Length);
        Le.Put16(header, 28, (ushort)(extra?.Length ?? 0));
        Buffer.BlockCopy(nameBytes, 0, header, 30, nameBytes.Length);
        if (extra != null)
        {
            Buffer.BlockCopy(extra, 0, header, 30 + nameBytes.Length, extra.Length);
        }

        _counter.Write(header, 0, header.Length);
    }

    private void WriteDescriptor(uint crc, long compSize, long uncompSize)
    {
        var zip64Sizes = compSize > uint.MaxValue || uncompSize > uint.MaxValue;
        var descriptor = new byte[zip64Sizes ? 24 : 16];
        Le.Put32(descriptor, 0, ZipConstants.DataDescriptorSignature);
        Le.Put32(descriptor, 4, crc);
        if (zip64Sizes)
        {
            Le.Put64(descriptor, 8, (ulong)compSize);
            Le.Put64(descriptor, 16, (ulong)uncompSize);
        }
        else
        {
            Le.Put32(descriptor, 8, (uint)compSize);
            Le.Put32(descriptor, 12, (uint)uncompSize);
        }

        _counter.Write(descriptor, 0, descriptor.Length);
    }

    private void WriteCentralHeader(CentralRecord central)
    {
        var nameBytes = EncodeName(central.Name);
        var commentBytes = central.Comment != null ? _options.EntryNameEncoding.GetBytes(central.Comment) : Array.Empty<byte>();

        var extraParts = new List<byte[]>();

        if (central.EncryptionExtra != null && central.EncryptionExtraFieldId.HasValue)
        {
            var enc = new byte[4 + central.EncryptionExtra.Length];
            Le.Put16(enc, 0, central.EncryptionExtraFieldId.Value);
            Le.Put16(enc, 2, (ushort)central.EncryptionExtra.Length);
            Buffer.BlockCopy(central.EncryptionExtra, 0, enc, 4, central.EncryptionExtra.Length);
            extraParts.Add(enc);
        }

        var needsZip64 = central.CompressedSize > uint.MaxValue || central.UncompressedSize > uint.MaxValue
                         || central.LocalOffset > uint.MaxValue;
        if (needsZip64)
        {
            var zip64 = new byte[4 + 24];
            Le.Put16(zip64, 0, ZipConstants.ExtraFieldZip64);
            Le.Put16(zip64, 2, 24);
            Le.Put64(zip64, 4, (ulong)central.UncompressedSize);
            Le.Put64(zip64, 12, (ulong)central.CompressedSize);
            Le.Put64(zip64, 20, (ulong)central.LocalOffset);
            extraParts.Add(zip64);
        }

        var extraLen = 0;
        foreach (var part in extraParts)
        {
            extraLen += part.Length;
        }

        // MS-DOS host（0x00）+ 规范版本（zip64 条目 45，否则 20）
        var versionMadeBy = (ushort)(0x00 << 8 | (needsZip64 ? 45 : 20));
        var externalAttrs = central.IsDirectory ? 0x10u : 0x20u;

        var header = new byte[46 + nameBytes.Length + extraLen + commentBytes.Length];
        Le.Put32(header, 0, ZipConstants.CentralHeaderSignature);
        Le.Put16(header, 4, versionMadeBy);
        Le.Put16(header, 6, (ushort)(needsZip64 ? 45 : 20));
        Le.Put16(header, 8, (ushort)(ZipConstants.FlagDataDescriptor | (_utf8Names ? ZipConstants.FlagUtf8 : 0) |
                                     (central.IsEncrypted ? ZipConstants.FlagEncrypted : 0)));
        Le.Put16(header, 10, central.Method);
        Le.Put16(header, 12, (ushort)central.DosTime);
        Le.Put16(header, 14, (ushort)central.DosDate);
        Le.Put32(header, 16, central.Crc);
        Le.Put32(header, 20, central.CompressedSize > uint.MaxValue ? uint.MaxValue : (uint)central.CompressedSize);
        Le.Put32(header, 24, central.UncompressedSize > uint.MaxValue ? uint.MaxValue : (uint)central.UncompressedSize);
        Le.Put16(header, 28, (ushort)nameBytes.Length);
        Le.Put16(header, 30, (ushort)extraLen);
        Le.Put16(header, 32, (ushort)commentBytes.Length);
        Le.Put16(header, 34, 0); // disk start
        Le.Put16(header, 36, 0); // internal attrs
        Le.Put32(header, 38, externalAttrs);
        Le.Put32(header, 42, central.LocalOffset > uint.MaxValue ? uint.MaxValue : (uint)central.LocalOffset);
        Buffer.BlockCopy(nameBytes, 0, header, 46, nameBytes.Length);

        var pos = 46 + nameBytes.Length;
        foreach (var part in extraParts)
        {
            Buffer.BlockCopy(part, 0, header, pos, part.Length);
            pos += part.Length;
        }

        if (commentBytes.Length > 0)
        {
            Buffer.BlockCopy(commentBytes, 0, header, pos, commentBytes.Length);
        }

        _counter.Write(header, 0, header.Length);
    }

    private static void CopyPlain(Stream source, Stream target, CancellationToken ct)
    {
        var buffer = new byte[81920];
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            target.Write(buffer, 0, read);
        }
    }

    private static CompressionLevel MapLevel(CompressionLevelChoice level) => level switch
    {
        CompressionLevelChoice.Fastest => CompressionLevel.Fastest,
        CompressionLevelChoice.SmallestSize => CompressionLevel.Optimal,
        _ => CompressionLevel.Optimal,
    };

    private static bool IsUtf8(Encoding encoding) => encoding is UTF8Encoding;

    private static string NormalizeName(string name)
    {
        var n = name.Replace('\\', '/').TrimStart('/');
        while (n.Contains("//"))
        {
            n = n.Replace("//", "/");
        }

        return n;
    }

    private byte[] EncodeName(string name) => _options.EntryNameEncoding.GetBytes(name);

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
                // 自动收尾失败不遮蔽主异常（与门面 Dispose 语义一致）
            }
        }

        if (_ownsStream)
        {
            _output.Dispose();
        }
    }

    private sealed class CentralRecord
    {
        public CentralRecord(string name, ushort method, uint dosTime, uint dosDate, uint crc,
            long compressedSize, long uncompressedSize, long localOffset, ArchiveEntryMetadata metadata,
            byte[]? encryptionExtra, ushort? encryptionExtraFieldId, bool isDirectory, bool isEncrypted)
        {
            Name = name;
            Method = method;
            DosTime = dosTime;
            DosDate = dosDate;
            Crc = crc;
            CompressedSize = compressedSize;
            UncompressedSize = uncompressedSize;
            LocalOffset = localOffset;
            Comment = metadata.Comment;
            EncryptionExtra = encryptionExtra;
            EncryptionExtraFieldId = encryptionExtraFieldId;
            IsDirectory = isDirectory;
            IsEncrypted = isEncrypted;
        }

        public string Name { get; }
        public ushort Method { get; }
        public uint DosTime { get; }
        public uint DosDate { get; }
        public uint Crc { get; }
        public long CompressedSize { get; }
        public long UncompressedSize { get; }
        public long LocalOffset { get; }
        public string? Comment { get; }
        public byte[]? EncryptionExtra { get; }
        public ushort? EncryptionExtraFieldId { get; }
        public bool IsDirectory { get; }
        public bool IsEncrypted { get; }
    }
}
