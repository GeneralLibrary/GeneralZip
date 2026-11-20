using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Internal;

namespace GeneralZip.Formats.Iso;

/// <summary>
/// ISO9660 光盘镜像读取（纯 C# 自研，只读）。
/// 优先 Joliet（UCS-2 补充卷）与 Rock Ridge NM 文件名，回退 ISO Level 1 基础名。
/// 多卷集合/UDF 混合镜像取 ISO9660 视图。写入不支持。
/// </summary>
public sealed class IsoFormat : IArchiveFormat
{
    private const int SectorSize = 2048;
    private const int PvdLba = 16;

    public ArchiveFormatInfo Info { get; } = new(
        "ISO", new[] { ".iso" },
        FormatCapabilities.Read | FormatCapabilities.SeekableRead,
        "ISO9660 (+Joliet/Rock Ridge name extensions), read-only");

    public bool MatchesSignature(Stream stream)
    {
        long restorePos = -1;
        if (stream.CanSeek) restorePos = stream.Position;

        try
        {
            stream.Seek(PvdLba * SectorSize + 1, SeekOrigin.Begin);
            var buf = new byte[5];
            var total = 0;
            while (total < buf.Length)
            {
                var n = stream.Read(buf, total, buf.Length - total);
                if (n <= 0) return false;
                total += n;
            }

            return buf[0] == (byte)'C' && buf[1] == (byte)'D' && buf[2] == (byte)'0'
                   && buf[3] == (byte)'0' && buf[4] == (byte)'1';
        }
        catch (IOException)
        {
            return false;
        }
        finally
        {
            if (restorePos >= 0) stream.Position = restorePos;
        }
    }

    public bool MatchesExtension(string extension)
        => extension.Equals(".iso", StringComparison.OrdinalIgnoreCase);

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        if (!stream.CanSeek)
        {
            throw new NotSupportedException("ISO reading requires a seekable stream");
        }

        return new IsoReader(stream, ownsStream: false);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
        => throw new UnsupportedFormatException("ISO9660 writing is not supported (read-only format)");

    internal sealed class IsoEntryData
    {
        public string Name = string.Empty;
        public long Lba;
        public long Size;
        public bool IsDirectory;
        public DateTimeOffset MTime;
        public long DataOffset => Lba * SectorSize;
    }

    internal sealed class IsoReader : IArchiveReader
    {
        private readonly Stream _stream;
        private readonly bool _ownsStream;
        private readonly List<IsoEntryData> _flat = new();
        private readonly List<IArchiveEntry> _entries = new();

        public IsoReader(Stream stream, bool ownsStream)
        {
            _stream = stream;
            _ownsStream = ownsStream;

            var (rootLba, rootSize, useUcs2) = LocateVolume(stream);
            var visited = new HashSet<long>();
            Walk(stream, rootLba, rootSize, string.Empty, useUcs2, visited, depth: 0);
        }

        /// <summary>定位 PVD 根目录；存在 Joliet SVD 时取其根（UCS-2 名称）。</summary>
        private static (long lba, long size, bool ucs2) LocateVolume(Stream s)
        {
            // 扫描 PVD..SVD 区（最多到 LBA 32）
            var jolietRoot = (lba: 0L, size: 0L);
            for (var lba = PvdLba; lba < PvdLba + 16; lba++)
            {
                var sector = ReadSector(s, lba);
                if (sector[1] != (byte)'C' || sector[2] != (byte)'D' || sector[3] != (byte)'0'
                    || sector[4] != (byte)'0' || sector[5] != (byte)'1')
                {
                    break; // 卷描述符序列结束（terminator 亦不匹配）
                }

                var type = sector[0];
                if (type == 1)
                {
                    // 主卷描述符：兜底根
                    var root = ParseDirectoryRecord(sector, 156);
                    jolietRoot = (root.lba, root.size);
                    continue;
                }

                if (type == 2)
                {
                    // 补充卷描述符：Joliet 检测（escape sequences %/@ %/C %/E，偏移 88..）
                    var e = sector[88];
                    if ((e == 0x25 && sector[89] == 0x2F && (sector[90] == 0x40 || sector[90] == 0x43 || sector[90] == 0x45)))
                    {
                        var root = ParseDirectoryRecord(sector, 156);
                        return (root.lba, root.size, true); // Joliet 优先
                    }
                }
            }

            if (jolietRoot.lba == 0)
            {
                throw new ArchiveCorruptedException("ISO9660: no primary volume descriptor with a root directory found");
            }

            return (jolietRoot.lba, jolietRoot.size, false);
        }

        private static byte[] ReadSector(Stream s, long lba)
        {
            var buf = new byte[SectorSize];
            s.Position = lba * SectorSize;
            var total = 0;
            while (total < SectorSize)
            {
                var n = s.Read(buf, total, SectorSize - total);
                if (n <= 0)
                {
                    throw new ArchiveCorruptedException($"ISO9660: unexpected end of file at LBA {lba}");
                }

                total += n;
            }

            return buf;
        }

        private static (long lba, long size) ParseDirectoryRecord(byte[] sector, int offset)
        {
            // LBA 双端（LE @+2，BE @+6）、大小双端（LE @+10，BE @+14）
            var lba = BitConverter.ToUInt32(sector, offset + 2);
            var size = BitConverter.ToUInt32(sector, offset + 10);
            return (lba, size);
        }

        private void Walk(Stream s, long dirLba, long dirSize, string prefix, bool ucs2, HashSet<long> visited, int depth)
        {
            if (depth > 1024)
            {
                throw new ArchiveCorruptedException("ISO9660 directory nesting exceeds the supported limit");
            }

            if (!visited.Add(dirLba))
            {
                return;
            }

            var extentStart = dirLba * SectorSize;
            for (var sectorOffset = 0L; sectorOffset < dirSize; sectorOffset += SectorSize)
            {
                var sector = ReadSector(s, (extentStart + sectorOffset) / SectorSize);
                for (var offset = 0; offset < SectorSize; )
                {
                    var len = sector[offset];
                    if (len == 0)
                    {
                        // 记录不跨扇区：0 填充 → 结束本扇区
                        break;
                    }

                    if (len < 34 || offset + len > sector.Length)
                    {
                        throw new ArchiveCorruptedException("ISO9660: invalid directory record length");
                    }

                    var nameLen = sector[offset + 32];
                    if (33 + nameLen > len)
                    {
                        throw new ArchiveCorruptedException("ISO9660: directory identifier exceeds its record");
                    }

                    var extLba = BitConverter.ToUInt32(sector, offset + 2);
                    var extSize = BitConverter.ToUInt32(sector, offset + 10);
                    var flags = sector[offset + 25];
                    var isDir = (flags & 0x02) != 0;

                    var identifierOffset = offset + 33;
                    if (nameLen == 1 && sector[identifierOffset] <= 1)
                    {
                        offset += len;
                        continue;
                    }

                    var name = DecodeName(sector, identifierOffset, nameLen, ucs2);
                    var systemUse = identifierOffset + nameLen + ((nameLen & 1) == 0 ? 1 : 0);
                    name = ApplyRockRidge(sector, systemUse, offset + len, name);

                    if (name.Length != 0)
                    {
                        var mtime = DecodeIsoTime(sector, offset + 18);
                        var fullName = prefix.Length > 0 ? prefix + "/" + name : name;
                        var data = new IsoEntryData
                        {
                            Name = isDir ? fullName + "/" : fullName,
                            Lba = extLba,
                            Size = extSize,
                            IsDirectory = isDir,
                            MTime = mtime,
                        };
                        _entries.Add(new IsoEntryView(data, this));

                        if (isDir)
                        {
                            Walk(s, extLba, extSize, fullName, ucs2, visited, depth + 1);
                        }
                    }

                    offset += len;
                }
            }
        }

        private static string DecodeName(byte[] sector, int offset, int nameLen, bool ucs2)
        {
            if (ucs2)
            {
                var sb = new StringBuilder(nameLen / 2);
                for (var i = 0; i + 1 < nameLen; i += 2)
                {
                    sb.Append((char)((sector[offset + i] << 8) | sector[offset + i + 1])); // UCS-2 BE
                }

                var name = sb.ToString();
                var version = name.IndexOf(';');
                if (version >= 0) name = name.Substring(0, version);
                return name.Length > 0 && name[name.Length - 1] == '.' ? name.Substring(0, name.Length - 1) : name;
            }

            var raw = Encoding.ASCII.GetString(sector, offset, nameLen);
            var idx = raw.IndexOf(';');
            if (idx >= 0)
            {
                raw = raw.Substring(0, idx); // 剥掉 ";1" 版本号
            }

            return raw.TrimEnd('.');
        }

        /// <summary>Rock Ridge：System Use 区里的 NM 条目提供 POSIX 文件名。</summary>
        /// <summary>Rock Ridge：System Use 区里的 NM 条目提供 POSIX 文件名。</summary>
        private static string ApplyRockRidge(byte[] sector, int systemUseOffset, int recordEnd, string fallback)
        {
            var pos = systemUseOffset;
            var name = new StringBuilder();
            while (pos + 4 <= recordEnd)
            {
                var sig0 = (char)sector[pos];
                var sig1 = (char)sector[pos + 1];
                var len = sector[pos + 2];
                if (len < 4 || pos + len > recordEnd)
                {
                    break;
                }

                if (sig0 == 'N' && sig1 == 'M')
                {
                    name.Append(Encoding.UTF8.GetString(sector, pos + 5, len - 5));
                }

                pos += len;
            }

            return name.Length > 0 ? name.ToString() : fallback;
        }

        private static DateTimeOffset DecodeIsoTime(byte[] sector, int offset)
        {
            // 9.1.5: 7 字节 (year-1900, month, day, hour, minute, second, gmt offset*15min)
            var year = sector[offset] + 1900;
            try
            {
                return new DateTimeOffset(year, sector[offset + 1], sector[offset + 2],
                    sector[offset + 3], sector[offset + 4], sector[offset + 5], TimeSpan.Zero);
            }
            catch (ArgumentOutOfRangeException)
            {
                return new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
            }
        }

        public ArchiveFormatInfo Format { get; } = new(
            "ISO", new[] { ".iso" },
            FormatCapabilities.Read | FormatCapabilities.SeekableRead,
            "ISO9660 (+Joliet/Rock Ridge name extensions), read-only");

        public IReadOnlyList<IArchiveEntry> Entries => _entries;

        public bool IsEncrypted => false;

        public Stream OpenEntryStream(IArchiveEntry entry)
        {
            var view = (IsoEntryView)entry;
            return new PartialStream(_stream, view.Data.DataOffset, view.Data.Size);
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

        public void Dispose()
        {
            if (_ownsStream) _stream.Dispose();
        }

        private sealed class IsoEntryView : IArchiveEntry
        {
            public IsoEntryView(IsoEntryData data, IsoReader owner)
            {
                Data = data;
            }

            public IsoEntryData Data { get; }

            public string FullName => Data.Name;
            public string Name
            {
                get
                {
                    var idx = Data.Name.LastIndexOf('/');
                    return idx >= 0 ? Data.Name.Substring(idx + 1) : Data.Name;
                }
            }

            public long Size => Data.Size;
            public long CompressedSize => Data.Size;
            public DateTimeOffset? LastWriteTime => Data.MTime;
            public bool IsDirectory => Data.IsDirectory;
            public bool IsEncrypted => false;
            public string? EncryptionAlgorithm => null;
            public uint? Crc32 => null;
            public string? Comment => null;
        }
    }
}
