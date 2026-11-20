using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using GeneralZip.Abstractions;
using GeneralZip.Internal;

namespace GeneralZip.Formats.Cpio;

/// <summary>
/// CPIO 归档格式（纯 C# 自研，无第三方依赖）。
/// 读取：SVR4 newc（"070701"）、CRC 变体（"070702"）、odc 旧 ASCII（"070707"）、portable binary（0x71C7）；
/// 写入：newc（最通用，GNU cpio -H newc 互通）。符号链接以数据段承载目标路径（S_IFLNK）。
/// </summary>
public sealed class CpioFormat : IArchiveFormat
{
    private const string MagicNewc = "070701";
    private const string MagicCrc = "070702";
    private const string MagicOdc = "070707";
    private const string TrailerName = "TRAILER!!!";

    private const uint SIfmt = 0xF000u;
    private const uint SIfReg = 0x8000u;
    private const uint SIfDir = 0x4000u;
    private const uint SIfLnk = 0xA000u;

    public ArchiveFormatInfo Info { get; } = new(
        "CPIO", new[] { ".cpio" },
        FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.SeekableRead,
        "cpio: newc/odc/binary read, newc write");

    public bool MatchesSignature(Stream stream)
    {
        long restorePos = -1;
        if (stream.CanSeek) restorePos = stream.Position;

        try
        {
            var prefix = new byte[6];
            var total = 0;
            while (total < prefix.Length)
            {
                var n = stream.Read(prefix, total, prefix.Length - total);
                if (n <= 0) break;
                total += n;
            }

            if (total < 6) return total == 2 && prefix[0] == 0x71 && prefix[1] == 0xC7;

            var magic = System.Text.Encoding.ASCII.GetString(prefix, 0, 6);
            return magic == MagicNewc || magic == MagicCrc || magic == MagicOdc
                   || (prefix[0] == 0x71 && prefix[1] == 0xC7);
        }
        finally
        {
            if (restorePos >= 0) stream.Position = restorePos;
        }
    }

    public bool MatchesExtension(string extension)
        => extension.Equals(".cpio", StringComparison.OrdinalIgnoreCase);

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        if (!stream.CanSeek)
        {
            throw new NotSupportedException("CPIO reading requires a seekable stream");
        }

        return new CpioReader(stream, ownsStream: false);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
        => new CpioWriter(stream, ownsStream: false);

    // ---------- newc 头解析/序列化 ----------

    internal sealed class CpioEntryData
    {
        public string Name = string.Empty;
        public uint Mode;
        public long Size;
        public DateTimeOffset MTime;
        public long DataOffset;
        public bool IsDirectory => (Mode & SIfmt) == SIfDir;
        public bool IsSymlink => (Mode & SIfmt) == SIfLnk;
    }

    private static readonly char[] HexTrim = { ' ' };

    /// <summary>流式枚举 newc/odc/binary 头部（供读取器与探测共用）。返回 null = 归档结束。</summary>
    internal static CpioEntryData? ReadHeader(Stream stream, BinaryReader reader, out string? formatKind)
    {
        formatKind = null;
        var head = reader.ReadBytes(6);
        if (head.Length < 6)
        {
            return null;
        }

        var magic = System.Text.Encoding.ASCII.GetString(head);
        if (magic == MagicNewc || magic == MagicCrc)
        {
            formatKind = "newc";
            // 13 个 8 位十六进制字段：ino mode uid gid nlink mtime filesize devmaj devmin rmaj rmin namesize check
            var fields = new string[13];
            for (var i = 0; i < fields.Length; i++)
            {
                fields[i] = System.Text.Encoding.ASCII.GetString(reader.ReadBytes(8));
            }

            var mode = ParseHex(fields[1]);
            var mtime = ParseHex(fields[5]);
            var fileSize = ParseHex(fields[6]);
            var nameSize = ParseHex(fields[11]);

            var nameBytes = reader.ReadBytes((int)nameSize);
            var name = System.Text.Encoding.UTF8.GetString(nameBytes, 0, nameBytes.Length).TrimEnd('\0');
            AlignTo4(stream);

            if (name == TrailerName || name.Length == 0)
            {
                AlignTo4(stream);
                return null;
            }

            var offset = stream.Position;
            stream.Seek(fileSize, SeekOrigin.Current);
            AlignTo4(stream);

            return new CpioEntryData
            {
                Name = name,
                Mode = mode,
                Size = fileSize,
                MTime = DateTimeOffset.FromUnixTimeSeconds(mtime),
                DataOffset = offset,
            };
        }

        if (magic == MagicOdc)
        {
            formatKind = "odc";
            // dev, ino, mode, uid, gid, nlink, rdev, mtime, namesize, filesize
            var widths = new[] { 6, 6, 6, 6, 6, 6, 6, 11, 6, 11 };
            var fields = new string[widths.Length];
            for (var i = 0; i < fields.Length; i++)
            {
                var bytes = reader.ReadBytes(widths[i]);
                if (bytes.Length != widths[i]) throw new ArchiveCorruptedException("Truncated CPIO odc header");
                fields[i] = System.Text.Encoding.ASCII.GetString(bytes);
            }

            var mode = ParseOctal(fields[2]);
            var mtime = ParseOctal(fields[7]);
            var nameSize = ParseOctal(fields[8]);
            var fileSize = ParseOctal(fields[9]);

            var nameBytes = reader.ReadBytes((int)nameSize);
            var name = System.Text.Encoding.UTF8.GetString(nameBytes, 0, nameBytes.Length).TrimEnd('\0');

            if (name == TrailerName || name.Length == 0)
            {
                return null;
            }

            var offset = stream.Position;
            stream.Seek(fileSize, SeekOrigin.Current);

            return new CpioEntryData
            {
                Name = name,
                Mode = mode,
                Size = fileSize,
                MTime = DateTimeOffset.FromUnixTimeSeconds(mtime),
                DataOffset = offset,
            };
        }

        // portable binary（LE 0x71C7；BE 魔数为 0xC771）
        stream.Position -= 6;
        var b0 = reader.ReadByte();
        var b1 = reader.ReadByte();
        if (b0 == 0x71 && b1 == 0xC7 || b0 == 0xC7 && b1 == 0x71)
        {
            formatKind = "binary";
            var little = b0 == 0x71;
            ushort ReadU16()
            {
                var lo = reader.ReadByte();
                var hi = reader.ReadByte();
                return little ? (ushort)(lo | (hi << 8)) : (ushort)((lo << 8) | hi);
            }

            _ = ReadU16(); // c_dev
            var ino = ReadU16();
            var mode = ReadU16();
            var uid = ReadU16();
            var gid = ReadU16();
            var nlink = ReadU16();
            _ = ReadU16(); // c_rdev
            var mtimeHi = (uint)ReadU16() << 16;
            var mtimeLo = ReadU16();
            var nameSize = ReadU16();
            var fileSizeHi = (uint)ReadU16() << 16;
            var fileSizeLo = ReadU16();

            var nameBytes = reader.ReadBytes(nameSize);
            if (nameBytes.Length != nameSize) throw new ArchiveCorruptedException("Truncated CPIO binary name");
            var name = System.Text.Encoding.UTF8.GetString(nameBytes, 0, nameBytes.Length).TrimEnd('\0');
            AlignTo2(stream);

            if (name == TrailerName || name.Length == 0)
            {
                return null;
            }

            var fileSize = fileSizeHi | fileSizeLo;
            var offset = stream.Position;
            stream.Seek(fileSize, SeekOrigin.Current);
            AlignTo2(stream);

            return new CpioEntryData
            {
                Name = name,
                Mode = mode,
                Size = fileSize,
                MTime = DateTimeOffset.FromUnixTimeSeconds(mtimeHi | mtimeLo),
                DataOffset = offset,
            };
        }

        throw new ArchiveCorruptedException($"Invalid CPIO magic: {magic}");
    }

    /// <summary>newc 对齐：把当前流位置补齐到 4 字节边界（GNU cpio 语义为绝对位置对齐）。</summary>
    private static void AlignTo4(Stream stream)
    {
        var pad = (4 - (stream.Position % 4)) % 4;
        if (pad > 0)
        {
            stream.Seek(pad, SeekOrigin.Current);
        }
    }

    private static void AlignTo2(Stream stream)
    {
        if ((stream.Position & 1) != 0) stream.Seek(1, SeekOrigin.Current);
    }

    private static uint ParseHex(string s) => uint.Parse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static uint ParseOctal(string s) => Convert.ToUInt32(s.Length == 0 ? "0" : s, 8);

    // ---------- 读取器 ----------

    private sealed class CpioReader : IArchiveReader
    {
        private readonly Stream _stream;
        private readonly bool _ownsStream;
        private readonly List<(CpioEntryData data, IArchiveEntry entry)> _entries = new();

        public CpioReader(Stream stream, bool ownsStream)
        {
            _stream = stream;
            _ownsStream = ownsStream;

            using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
            string? kind = null;
            while (true)
            {
                CpioEntryData? data;
                try
                {
                    data = ReadHeader(stream, reader, out var k);
                    kind ??= k;
                }
                catch (EndOfStreamException)
                {
                    break;
                }

                if (data == null)
                {
                    break;
                }

                var entry = new CpioEntryView(data, Format);
                _entries.Add((data, entry));
            }
        }

        public ArchiveFormatInfo Format { get; } = new(
            "CPIO", new[] { ".cpio" },
            FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.SeekableRead,
            "cpio: newc/odc/binary read, newc write");

        public IReadOnlyList<IArchiveEntry> Entries => _entries.ConvertAll(e => e.entry);

        public bool IsEncrypted => false;

        public Stream OpenEntryStream(IArchiveEntry entry)
        {
            var data = Find(entry);
            return new PartialStream(_stream, data.DataOffset, data.Size);
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

        private CpioEntryData Find(IArchiveEntry entry)
        {
            foreach (var (data, view) in _entries)
            {
                if (ReferenceEquals(view, entry))
                {
                    return data;
                }
            }

            throw new ArgumentException("Entry does not belong to this archive", nameof(entry));
        }

        public void Dispose()
        {
            if (_ownsStream) _stream.Dispose();
        }
    }

    private sealed class CpioEntryView : IArchiveEntry, IUnixEntry
    {
        private readonly CpioEntryData _data;

        public CpioEntryView(CpioEntryData data, ArchiveFormatInfo format)
        {
            _data = data;
        }

        public string FullName => _data.Name;
        public string Name
        {
            get
            {
                var idx = _data.Name.LastIndexOf('/');
                return idx >= 0 ? _data.Name.Substring(idx + 1) : _data.Name;
            }
        }

        public long Size => _data.IsSymlink || _data.IsDirectory ? _data.Size : _data.Size;
        public long CompressedSize => _data.Size;
        public DateTimeOffset? LastWriteTime => _data.MTime;
        public bool IsDirectory => _data.IsDirectory;
        public bool IsEncrypted => false;
        public string? EncryptionAlgorithm => null;
        public uint? Crc32 => null;
        public string? Comment => null;
        public uint? UnixMode => _data.Mode;

        /// <summary>符号链接目标在数据段中；此处只报告判定，目标内容经 OpenEntryStream 读取。</summary>
        public string? SymlinkTarget => null;
    }

    // ---------- 写入器（newc） ----------

    private sealed class CpioWriter : IArchiveWriter, IArchiveSymlinkWriter
    {
        private readonly Stream _output;
        private readonly bool _ownsStream;
        private uint _ino = 300_000; // 任意起始 i-node
        private long _bytesWritten;  // 绝对位置（newc 对齐按绝对位置计算）
        private bool _finished;

        public CpioWriter(Stream output, bool ownsStream)
        {
            _output = output;
            _ownsStream = ownsStream;
        }

        public ArchiveFormatInfo Info { get; } = new(
            "CPIO", new[] { ".cpio" },
            FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.SeekableRead,
            "cpio: newc/odc/binary read, newc write");

        public ArchiveWriteOptions Options { get; } = new();

        public void AddDirectoryEntry(string entryName, ArchiveEntryMetadata metadata)
            => WriteHeader(Normalize(entryName), SIfDir | 0x1EDu /*0755*/, 0, metadata);

        public void AddSymlink(string entryName, string target, ArchiveEntryMetadata metadata)
        {
            var targetBytes = System.Text.Encoding.UTF8.GetBytes(target);
            WriteHeader(Normalize(entryName), SIfLnk | 0x1FFu /*0777*/, targetBytes.Length, metadata);
            WriteData(targetBytes);
        }

        public void AddEntry(string entryName, Stream content, ArchiveEntryMetadata metadata, CancellationToken cancellationToken)
        {
            var name = Normalize(entryName);
            var mode = SIfReg | 0x1A4u; // 0644 默认
            if (metadata.UnixMode is { } um)
            {
                mode = (um & SIfmt) == SIfReg ? um : SIfReg | (um & 0xFFF);
            }

            if (metadata.Size >= 0)
            {
                WriteHeader(name, mode, metadata.Size, metadata);
                CopyData(content, metadata.Size, cancellationToken);
            }
            else
            {
                // 未知大小：缓冲到内存（cpio 头部必须前置声明 filesize）
                using var ms = new MemoryStream();
                content.CopyTo(ms, 81920);
                WriteHeader(name, mode, ms.Length, metadata);
                WriteData(ms.ToArray());
            }
        }

        private void WriteHeader(string name, uint mode, long size, ArchiveEntryMetadata metadata)
        {
            var nameBytes = System.Text.Encoding.UTF8.GetBytes(name.Length == 0 ? "\0" : name + "\0");
            var mtime = (metadata.LastWriteTime ?? DateTimeOffset.Now).ToUnixTimeSeconds();

            var header = new System.Text.StringBuilder();
            header.Append(MagicNewc);
            foreach (var value in new long[]
            {
                _ino++, mode, 0 /*uid*/, 0 /*gid*/, 1 /*nlink*/, mtime, size,
                0 /*devmajor*/, 0, 0, 0, nameBytes.Length, 0 /*check*/,
            })
            {
                header.Append(value.ToString("X8", CultureInfo.InvariantCulture));
            }

            var headerBytes = System.Text.Encoding.ASCII.GetBytes(header.ToString());
            _output.Write(headerBytes, 0, headerBytes.Length);
            _output.Write(nameBytes, 0, nameBytes.Length);
            _bytesWritten += headerBytes.Length + nameBytes.Length;
            Pad4();
        }

        private void CopyData(Stream content, long size, CancellationToken ct)
        {
            var buffer = new byte[81920];
            long written = 0;
            int read;
            while (written < size && (read = content.Read(buffer, 0, (int)Math.Min(buffer.Length, size - written))) > 0)
            {
                ct.ThrowIfCancellationRequested();
                _output.Write(buffer, 0, read);
                written += read;
            }

            if (written != size)
            {
                throw new IOException($"CPIO: source stream ran short for declared size {size} (got {written})");
            }

            _bytesWritten += written;
            Pad4();
        }

        private void WriteData(byte[] bytes)
        {
            _output.Write(bytes, 0, bytes.Length);
            _bytesWritten += bytes.Length;
            Pad4();
        }

        /// <summary>newc 对齐：按绝对写位置补齐 4 字节边界。</summary>
        private void Pad4()
        {
            var pad = (int)((4 - (_bytesWritten % 4)) % 4);
            for (var i = 0; i < pad; i++)
            {
                _output.WriteByte(0);
            }

            _bytesWritten += pad;
        }

        private static string Normalize(string name)
        {
            var n = name.Replace('\\', '/').TrimStart('/');
            while (n.Contains("//"))
            {
                n = n.Replace("//", "/");
            }

            return n;
        }

        public void Finish(CancellationToken cancellationToken)
        {
            if (_finished) return;
            _finished = true;

            // trailer + 512 块对齐（GNU cpio 惯例）
            var trailerName = System.Text.Encoding.UTF8.GetBytes(TrailerName + "\0");
            var header = new System.Text.StringBuilder();
            header.Append(MagicNewc);
            foreach (var value in new long[] { _ino++, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, trailerName.Length, 0 })
            {
                header.Append(value.ToString("X8", CultureInfo.InvariantCulture));
            }

            var headerBytes = System.Text.Encoding.ASCII.GetBytes(header.ToString());
            _output.Write(headerBytes, 0, headerBytes.Length);
            _output.Write(trailerName, 0, trailerName.Length);
            _bytesWritten += headerBytes.Length + trailerName.Length;
            Pad4();

            var blockPad = (int)((512 - (_bytesWritten % 512)) % 512);
            for (var i = 0; i < blockPad; i++)
            {
                _output.WriteByte(0);
            }

            _bytesWritten += blockPad;
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

        public void Dispose()
        {
            if (!_finished)
            {
                try { Finish(CancellationToken.None); } catch { /* 不遮蔽主异常 */ }
            }

            if (_ownsStream)
            {
                _output.Dispose();
            }
        }
    }
}
