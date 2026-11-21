using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using GeneralZip.Internal;

namespace GeneralZip.Formats.Zip;

/// <summary>ZIP 常量与结构解析。</summary>
internal static class ZipConstants
{
    public const uint LocalHeaderSignature = 0x04034B50;
    public const uint CentralHeaderSignature = 0x02014B50;
    public const uint EndOfCentralDirectorySignature = 0x06054B50;
    public const uint Zip64EndOfCentralDirectorySignature = 0x06064B50;
    public const uint Zip64EndOfCentralDirectoryLocatorSignature = 0x07064B50;
    public const uint DataDescriptorSignature = 0x08074B50;

    public const ushort MethodStore = 0;
    public const ushort MethodDeflate = 8;
    public const ushort MethodBZip2 = 12;
    public const ushort MethodLzma = 14;
    public const ushort MethodZstd = 93;
    public const ushort MethodEncryptedMarker = 99;

    public const ushort ExtraFieldZip64 = 0x0001;

    // 通用目的标志位
    public const ushort FlagEncrypted = 0x0001;
    public const ushort FlagDataDescriptor = 0x0008;
    public const ushort FlagUtf8 = 0x0800;

    /// <summary>
    /// APPNOTE 规定：无 UTF-8 标志的条目名/注释默认按 IBM437（CP437）解码。
    /// 内置单字节表实现，避免引入 System.Text.Encoding.CodePages 依赖（保持 AOT 兼容与零第三方依赖约束）。
    /// </summary>
    internal static string DecodeIbm437(byte[] raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (var b in raw)
        {
            if (b < 0x80)
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append(Ibm437High[b - 0x80]);
            }
        }
        return sb.ToString();
    }

    // IBM437 高半区（0x80–0xFF）映射表，按码位顺序排列。
    private const string Ibm437High =
        "\u00C7\u00FC\u00E9\u00E2\u00E4\u00E0\u00E5\u00E7\u00EA\u00EB\u00E8\u00EF\u00EE\u00EC\u00C4\u00C5" +
        "\u00C9\u00E6\u00C6\u00F4\u00F6\u00F2\u00FB\u00F9\u00FF\u00D6\u00DC\u00A2\u00A3\u00A5\u20A7\u0192" +
        "\u00E1\u00ED\u00F3\u00FA\u00F1\u00D1\u00AA\u00BA\u00BF\u2310\u00AC\u00BD\u00BC\u00A1\u00AB\u00BB" +
        "\u2591\u2592\u2593\u2502\u2524\u2561\u2562\u2556\u2555\u2563\u2551\u2557\u255D\u255C\u255B\u2510" +
        "\u2514\u2534\u252C\u251C\u2500\u253C\u255E\u255F\u255A\u2554\u2569\u2566\u2560\u2550\u256C\u2567" +
        "\u2568\u2564\u2565\u2559\u2558\u2552\u2553\u256B\u256A\u2518\u250C\u2588\u2584\u258C\u2590\u2580" +
        "\u03B1\u00DF\u0393\u03C0\u03A3\u03C3\u00B5\u03C4\u03A6\u0398\u03A9\u03B4\u221E\u03C6\u03B5\u2229" +
        "\u2261\u00B1\u2265\u2264\u2320\u2321\u00F7\u2248\u00B0\u2219\u00B7\u221A\u207F\u00B2\u25A0\u00A0";
}

/// <summary>中央目录条目解析结果。</summary>
internal sealed class ZipCentralEntry
{
    public ushort VersionMadeBy { get; set; }
    public ushort Flags { get; set; }
    public ushort Method { get; set; }
    public uint DosTime { get; set; }
    public uint DosDate { get; set; }
    public uint Crc32 { get; set; }
    public long CompressedSize { get; set; }
    public long UncompressedSize { get; set; }
    public long LocalHeaderOffset { get; set; }
    public uint ExternalAttributes { get; set; }
    public byte[] NameRaw { get; set; } = Array.Empty<byte>();
    public byte[] Extra { get; set; } = Array.Empty<byte>();
    public byte[] CommentRaw { get; set; } = Array.Empty<byte>();

    public bool IsUtf8 => (Flags & ZipConstants.FlagUtf8) != 0;
    public bool IsEncryptedFlag => (Flags & ZipConstants.FlagEncrypted) != 0;
    public bool UsesDataDescriptor => (Flags & ZipConstants.FlagDataDescriptor) != 0;

    public string DecodeName(Encoding? fallback)
    {
        if (IsUtf8) return Encoding.UTF8.GetString(NameRaw);
        return Decode(NameRaw, fallback);
    }

    public string DecodeComment(Encoding? fallback)
    {
        if (IsUtf8) return Encoding.UTF8.GetString(CommentRaw);
        return Decode(CommentRaw, fallback);
    }

    private static string Decode(byte[] raw, Encoding? fallback)
    {
        if (raw.Length == 0) return string.Empty;
        if (fallback != null) return fallback.GetString(raw);
        return ZipConstants.DecodeIbm437(raw);
    }
}

/// <summary>ZIP 结构解析工具（中央目录、EOCD、Zip64）。</summary>
internal static class ZipStructure
{
    /// <summary>定位并解析中央目录；返回条目与归档注释。</summary>
    public static (List<ZipCentralEntry> entries, string? archiveComment) ReadCentralDirectory(Stream stream)
    {
        var eocd = FindEndOfCentralDirectory(stream)
                   ?? throw new ArchiveCorruptedException("ZIP end of central directory (EOCD) not found: file is corrupt or not a ZIP archive");

        long totalEntries = eocd.TotalEntries;
        long cdSize = eocd.CentralDirectorySize;
        long cdOffset = eocd.CentralDirectoryOffset;

        // Zip64 探测
        if (totalEntries == 0xFFFF || cdSize == 0xFFFFFFFF || cdOffset == 0xFFFFFFFF)
        {
            var zip64 = TryReadZip64EndOfCentralDirectory(stream, eocd.EndPosition);
            if (zip64.HasValue)
            {
                (totalEntries, cdSize, cdOffset) = zip64.Value;
            }
        }

        var entries = new List<ZipCentralEntry>((int)Math.Min(totalEntries, int.MaxValue));
        if (totalEntries == 0)
        {
            return (entries, eocd.ArchiveComment);
        }

        if (cdOffset < 0 || stream.Length < cdOffset + cdSize)
        {
            throw new ArchiveCorruptedException("Central directory offset out of bounds");
        }

        stream.Position = cdOffset;
        for (long i = 0; i < totalEntries; i++)
        {
            entries.Add(ReadCentralEntry(stream));
        }

        return (entries, eocd.ArchiveComment);
    }

    private static ZipCentralEntry ReadCentralEntry(Stream stream)
    {
        var sig = Le.ReadU32(stream);
        if (sig != ZipConstants.CentralHeaderSignature)
        {
            throw new ArchiveCorruptedException($"Invalid central directory entry signature: 0x{sig:X8}");
        }

        var entry = new ZipCentralEntry();
        entry.VersionMadeBy = Le.ReadU16(stream);
        Le.ReadU16(stream); // version needed to extract
        entry.Flags = Le.ReadU16(stream);
        entry.Method = Le.ReadU16(stream);
        entry.DosTime = Le.ReadU16(stream);
        entry.DosDate = Le.ReadU16(stream);
        entry.Crc32 = Le.ReadU32(stream);
        entry.CompressedSize = Le.ReadU32(stream);
        entry.UncompressedSize = Le.ReadU32(stream);

        var nameLen = Le.ReadU16(stream);
        var extraLen = Le.ReadU16(stream);
        var commentLen = Le.ReadU16(stream);
        Le.ReadU16(stream); // disk start
        Le.ReadU16(stream); // internal attributes
        entry.ExternalAttributes = Le.ReadU16(stream) | ((uint)Le.ReadU16(stream) << 16);
        entry.LocalHeaderOffset = Le.ReadU32(stream);

        entry.NameRaw = Le.ReadBytes(stream, nameLen);
        entry.Extra = Le.ReadBytes(stream, extraLen);
        entry.CommentRaw = Le.ReadBytes(stream, commentLen);

        // Zip64 扩展（0x0001）：仅当对应固定字段为 0xFFFFFFFF 时才存在对应字段
        if (entry.UncompressedSize == 0xFFFFFFFF || entry.CompressedSize == 0xFFFFFFFF || entry.LocalHeaderOffset == 0xFFFFFFFF)
        {
            var (uncomp, comp, offset) = ParseZip64Extra(entry.Extra, entry.UncompressedSize, entry.CompressedSize, entry.LocalHeaderOffset);
            entry.UncompressedSize = uncomp;
            entry.CompressedSize = comp;
            entry.LocalHeaderOffset = offset;
        }

        return entry;
    }

    private static (long uncomp, long comp, long offset) ParseZip64Extra(byte[] extra, long uncomp, long comp, long offset)
    {
        var pos = 0;
        while (pos + 4 <= extra.Length)
        {
            var id = Le.U16(extra, pos);
            var size = Le.U16(extra, pos + 2);
            pos += 4;
            if (id == ZipConstants.ExtraFieldZip64)
            {
                var end = pos + size;
                if (uncomp == 0xFFFFFFFF && pos + 8 <= end)
                {
                    uncomp = (long)Le.U64(extra, pos);
                    pos += 8;
                }

                if (comp == 0xFFFFFFFF && pos + 8 <= end)
                {
                    comp = (long)Le.U64(extra, pos);
                    pos += 8;
                }

                if (offset == 0xFFFFFFFF && pos + 8 <= end)
                {
                    offset = (long)Le.U64(extra, pos);
                    pos += 8;
                }

                return (uncomp, comp, offset);
            }

            pos += size;
        }

        throw new ArchiveCorruptedException("Zip64 marker present but Zip64 extra field is missing");
    }

    private sealed class Eocd
    {
        public Eocd(long totalEntries, long centralDirectorySize, long centralDirectoryOffset, long endPosition, string? archiveComment)
        {
            TotalEntries = totalEntries;
            CentralDirectorySize = centralDirectorySize;
            CentralDirectoryOffset = centralDirectoryOffset;
            EndPosition = endPosition;
            ArchiveComment = archiveComment;
        }

        public long TotalEntries { get; }
        public long CentralDirectorySize { get; }
        public long CentralDirectoryOffset { get; }
        public long EndPosition { get; }
        public string? ArchiveComment { get; }
    }

    private static Eocd? FindEndOfCentralDirectory(Stream stream)
    {
        var maxScan = Math.Min(stream.Length, 65557 + 22);
        var bufferSize = (int)maxScan;
        stream.Position = stream.Length - bufferSize;
        var buffer = Le.ReadBytes(stream, bufferSize);

        // 从尾部向前找签名
        for (var i = buffer.Length - 22; i >= 0; i--)
        {
            if (Le.U32(buffer, i) != ZipConstants.EndOfCentralDirectorySignature)
            {
                continue;
            }

            var commentLen = Le.U16(buffer, i + 20);
            var eocdEnd = i + 22 + commentLen;
            if (eocdEnd > buffer.Length)
            {
                continue; // 注释长度不符，继续找
            }

            return new Eocd(
                Le.U16(buffer, i + 10),
                Le.U32(buffer, i + 12),
                Le.U32(buffer, i + 16),
                stream.Length - bufferSize + eocdEnd,
                commentLen > 0 ? Encoding.UTF8.GetString(buffer, i + 22, commentLen) : null);
        }

        return null;
    }

    private static (long entries, long cdSize, long cdOffset)? TryReadZip64EndOfCentralDirectory(Stream stream, long eocdEndPosition)
    {
        const long locatorSize = 20;
        var locatorPos = eocdEndPosition - locatorSize;
        if (locatorPos < 0)
        {
            return null;
        }

        stream.Position = locatorPos;
        if (Le.ReadU32(stream) != ZipConstants.Zip64EndOfCentralDirectoryLocatorSignature)
        {
            return null;
        }

        Le.ReadU32(stream); // disk number
        var zip64EocdOffset = (long)Le.ReadU64(stream);
        if (zip64EocdOffset < 0 || stream.Length < zip64EocdOffset + 56)
        {
            throw new ArchiveCorruptedException("Zip64 EOCD offset out of bounds");
        }

        stream.Position = zip64EocdOffset;
        if (Le.ReadU32(stream) != ZipConstants.Zip64EndOfCentralDirectorySignature)
        {
            throw new ArchiveCorruptedException("Invalid Zip64 EOCD signature");
        }

        Le.ReadU64(stream); // size of record
        Le.ReadU16(stream); // version made by
        Le.ReadU16(stream); // version needed
        Le.ReadU32(stream); // disk number
        Le.ReadU32(stream); // cd disk
        var entriesThisDisk = (long)Le.ReadU64(stream);
        var totalEntries = (long)Le.ReadU64(stream);
        var cdSize = (long)Le.ReadU64(stream);
        var cdOffset = (long)Le.ReadU64(stream);
        return (totalEntries > 0 ? totalEntries : entriesThisDisk, cdSize, cdOffset);
    }

    /// <summary>解析并读取 local file header；返回 (flags, method, dataOffset)。</summary>
    public static (ushort flags, ushort method, long dataOffset) ReadLocalHeader(Stream stream, ZipCentralEntry central)
    {
        stream.Position = central.LocalHeaderOffset;
        var sig = Le.ReadU32(stream);
        if (sig != ZipConstants.LocalHeaderSignature)
        {
            throw new ArchiveCorruptedException(
                $"Invalid local header signature (0x{sig:X8}): archive is corrupt or the entry offset is misaligned");
        }

        Le.ReadU16(stream); // version needed
        var flags = Le.ReadU16(stream);
        var method = Le.ReadU16(stream);
        Le.ReadU16(stream); // time
        Le.ReadU16(stream); // date
        Le.ReadU32(stream); // crc
        Le.ReadU32(stream); // comp size (可能为 0，descriptor 模式)
        Le.ReadU32(stream); // uncomp size
        var nameLen = Le.ReadU16(stream);
        var extraLen = Le.ReadU16(stream);

        stream.Position += nameLen + extraLen;
        return (flags, method, stream.Position);
    }
}
