using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Internal;

namespace GeneralZip.Formats.Cab;

/// <summary>
/// CAB（Microsoft Cabinet）读取，纯 C# 自研，只读。
/// 支持存储方式 NONE（typeCompress=0）；MSZIP/LZX/Quantum 需跨块共享 32K 历史窗口的
/// 专有解码器，明确报不支持。写入不支持。
/// </summary>
public sealed class CabFormat : IArchiveFormat
{
    public ArchiveFormatInfo Info { get; } = new(
        "CAB", new[] { ".cab" },
        FormatCapabilities.Read | FormatCapabilities.SeekableRead,
        "Microsoft Cabinet, read-only (NONE/stored folders; MSZIP/LZX unsupported)");

    public bool MatchesSignature(Stream stream)
    {
        long restorePos = -1;
        if (stream.CanSeek) restorePos = stream.Position;

        try
        {
            var buf = new byte[4];
            var total = 0;
            while (total < buf.Length)
            {
                var n = stream.Read(buf, total, buf.Length - total);
                if (n <= 0) return false;
                total += n;
            }

            return buf[0] == (byte)'M' && buf[1] == (byte)'S' && buf[2] == (byte)'C' && buf[3] == (byte)'F';
        }
        finally
        {
            if (restorePos >= 0) stream.Position = restorePos;
        }
    }

    public bool MatchesExtension(string extension)
        => extension.Equals(".cab", StringComparison.OrdinalIgnoreCase);

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        if (!stream.CanSeek)
        {
            throw new NotSupportedException("CAB reading requires a seekable stream");
        }

        return new CabReader(stream, ownsStream: false);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
        => throw new UnsupportedFormatException("CAB writing is not supported (read-only format)");

    internal sealed class CabReader : IArchiveReader
    {
        private readonly Stream _stream;
        private readonly bool _ownsStream;
        private readonly List<(CabFolder folder, IArchiveEntry entry)> _entries = new();

        private sealed class CabFolder
        {
            public long DataOffset;
            public long DataLength; // 各块 payload 之和（虚拟长度）
            public ushort CompressionType;
            public List<(long payloadOffset, int payloadLen)> Blocks { get; } = new();
        }

        private sealed class CabFileData
        {
            public string Name = string.Empty;
            public long Size;
            public long OffsetInFolder;
            public DateTimeOffset MTime;
            public bool IsDirectory => (Attribs & 0x10) != 0; // A_NAME_IS_DIRECTORY
            public ushort Attribs;
        }

        public CabReader(Stream stream, bool ownsStream)
        {
            _stream = stream;
            _ownsStream = ownsStream;

            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
            stream.Position = 0;

            // CFHEADER
            if (reader.ReadBytes(4).Length < 4)
            {
                throw new ArchiveCorruptedException("CAB: truncated header");
            }

            stream.Position = 4;
            _ = reader.ReadUInt32(); // reserved1
            _ = reader.ReadUInt32(); // cbCabinet
            _ = reader.ReadUInt32(); // reserved2
            var coffFiles = reader.ReadUInt32();
            _ = reader.ReadUInt32(); // reserved3
            var verMinor = reader.ReadByte();
            var verMajor = reader.ReadByte();
            var cFolders = reader.ReadUInt16();
            var cFiles = reader.ReadUInt16();
            var flags = reader.ReadUInt16();
            _ = reader.ReadUInt16(); // setID
            _ = reader.ReadUInt16(); // iCabinet

            if (verMajor < 1 || verMajor > 3)
            {
                throw new UnsupportedFormatException($"CAB: unsupported version {verMajor}.{verMinor}");
            }

            // flags bit2 = RESERVE：跳过保留区与多卷字符串
            if ((flags & 0x0004) != 0)
            {
                var headerReserve = reader.ReadUInt16();
                var folderReserve = reader.ReadUInt16();
                var dataReserve = reader.ReadUInt16();
                stream.Position += headerReserve;
                if ((flags & 0x0001) != 0) // prev cabinet
                {
                    while (reader.ReadByte() != 0) { }
                    while (reader.ReadByte() != 0) { }
                }

                if ((flags & 0x0002) != 0) // next cabinet
                {
                    while (reader.ReadByte() != 0) { }
                    while (reader.ReadByte() != 0) { }
                }
            }

            // CFFOLDER × cFolders
            var folders = new CabFolder[cFolders];
            for (var i = 0; i < cFolders; i++)
            {
                var dataStart = reader.ReadUInt32();
                var cDataBlocks = reader.ReadUInt16();
                var typeCompress = reader.ReadUInt16();

                if ((flags & 0x0004) != 0)
                {
                    // folderReserve 在 header 解析期才知道：此处无字段（保留区仅存在于第一个 CFFOLDER 之前的布局约定中）
                }

                folders[i] = new CabFolder
                {
                    DataOffset = dataStart,
                    CompressionType = typeCompress,
                    // DataLength 在解析 CFDATA 块序列后填充（见下）
                };
                folders[i].DataLength = SumFolderData(stream, dataStart, cDataBlocks, typeCompress, folders[i]);
            }

            // CFFILE × cFiles（自 coffFiles 顺序排列）
            stream.Position = coffFiles;
            for (var i = 0; i < cFiles; i++)
            {
                var size = reader.ReadUInt32();
                var offsetInFolder = reader.ReadUInt32();
                var folderIndex = reader.ReadUInt16();
                var date = reader.ReadUInt16();
                var time = reader.ReadUInt16();
                var attribs = reader.ReadUInt16();

                var nameBytes = new List<byte>();
                byte b;
                while ((b = reader.ReadByte()) != 0)
                {
                    nameBytes.Add(b);
                }

                var name = Encoding.UTF8.GetString(nameBytes.ToArray());

                if (folderIndex == 0xFFFD || folderIndex == 0xFFFE || folderIndex == 0xFFFF)
                {
                    continue; // 跨卷 continued 文件：本卷不完整
                }

                if (folderIndex >= folders.Length)
                {
                    throw new ArchiveCorruptedException($"CAB: folder index {folderIndex} out of range");
                }

                var folder = folders[folderIndex];
                if ((folder.CompressionType & 0x000F) != 0)
                {
                    throw new UnsupportedFormatException(
                        $"CAB folder uses compression method {(folder.CompressionType & 0x000F)} (MSZIP/LZX/Quantum). " +
                        "GeneralZip supports NONE (stored) CAB folders only.");
                }

                var data = new CabFileData
                {
                    Name = name,
                    Size = size,
                    OffsetInFolder = offsetInFolder,
                    Attribs = attribs,
                    MTime = DecodeDosDateTime(date, time),
                };
                _entries.Add((folder, new CabEntryView(data, Format)));
            }
        }

        /// <summary>
        /// 顺序扫 CFDATA 块：记录每块 payload 的物理位置（块头 12 字节之后），
        /// 返回虚拟总长。NONE：payload 即原始数据。
        /// </summary>
        private long SumFolderData(Stream s, long dataStart, ushort cDataBlocks, ushort typeCompress, CabFolder folder)
        {
            var pos = s.Position;
            long total = 0;
            s.Position = dataStart;
            for (var i = 0; i < cDataBlocks; i++)
            {
                s.Position += 4; // checksum
                var cbData = ReadU16(s);
                var cbUncomp = ReadU16(s);
                var payloadOffset = s.Position;
                folder.Blocks.Add((payloadOffset, cbUncomp));
                total += cbUncomp;
                s.Position += cbData;
            }

            s.Position = pos;
            return total;
        }

        private static ushort ReadU16(Stream s)
        {
            var lo = s.ReadByte();
            var hi = s.ReadByte();
            if (hi < 0)
            {
                throw new EndOfStreamException();
            }

            return (ushort)(lo | (hi << 8));
        }

        private static DateTimeOffset DecodeDosDateTime(ushort date, ushort time)
        {
            try
            {
                var year = 1980 + (date >> 9);
                var month = (date >> 5) & 0xF;
                var day = date & 0x1F;
                var hour = time >> 11;
                var minute = (time >> 5) & 0x3F;
                var second = (time & 0x1F) * 2;
                return new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);
            }
            catch (ArgumentOutOfRangeException)
            {
                return new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
            }
        }

        public ArchiveFormatInfo Format { get; } = new(
            "CAB", new[] { ".cab" },
            FormatCapabilities.Read | FormatCapabilities.SeekableRead,
            "Microsoft Cabinet, read-only (NONE/stored folders; MSZIP/LZX unsupported)");

        public IReadOnlyList<IArchiveEntry> Entries => _entries.ConvertAll(e => e.entry);

        public bool IsEncrypted => false;

        public Stream OpenEntryStream(IArchiveEntry entry)
        {
            foreach (var (folder, view) in _entries)
            {
                if (!ReferenceEquals(view, entry))
                {
                    continue;
                }

                var data = ((CabEntryView)view).Data;
                if (data.IsDirectory)
                {
                    return Stream.Null;
                }

                return new CabinetFolderStream(this, _stream, folder, data.OffsetInFolder, data.Size);
            }

            throw new ArgumentException("Entry does not belong to this archive", nameof(entry));
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

        /// <summary>
        /// 文件夹数据流：把虚拟偏移（各块 payload 顺序拼接）翻译为物理偏移，
        /// 跨块读取自动衔接。NONE 文件夹的 payload 即原始字节。
        /// </summary>
        private sealed class CabinetFolderStream : Stream
        {
            private readonly Stream _base;
            private readonly CabFolder _folder;
            private readonly long _start; // 条目在虚拟空间中的起点
            private readonly long _length;
            private long _position;

            public CabinetFolderStream(CabReader owner, Stream baseStream, CabFolder folder, long virtualStart, long length)
            {
                _base = baseStream;
                _folder = folder;
                _start = virtualStart;
                _length = length;
                _position = 0;
            }

            private (long physOffset, int inBlock) Translate(long virtualOffset)
            {
                long acc = 0;
                foreach (var (payloadOffset, payloadLen) in _folder.Blocks)
                {
                    if (virtualOffset < acc + payloadLen)
                    {
                        return (payloadOffset + (virtualOffset - acc), (int)(virtualOffset - acc));
                    }

                    acc += payloadLen;
                }

                throw new ArchiveCorruptedException("CAB: virtual offset beyond folder data");
            }

            public override bool CanRead => true;
            public override bool CanSeek => true;
            public override bool CanWrite => false;
            public override long Length => _length;
            public override long Position { get => _position; set => _position = value; }

            public override int Read(byte[] buffer, int offset, int count)
            {
                var total = 0;
                while (total < count && _position < _length)
                {
                    var (physOffset, inBlock) = Translate(_start + _position);
                    var (_, payloadLen) = _folder.Blocks.Find(b => b.payloadOffset == physOffset - inBlock);
                    var availableInBlock = payloadLen - inBlock;
                    var want = (int)Math.Min(count - total, Math.Min(availableInBlock, _length - _position));
                    if (want <= 0)
                    {
                        break;
                    }

                    _base.Position = physOffset;
                    var read = _base.Read(buffer, offset + total, want);
                    if (read <= 0)
                    {
                        break;
                    }

                    _position += read;
                    total += read;
                }

                return total;
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                var target = origin switch
                {
                    SeekOrigin.Begin => offset,
                    SeekOrigin.Current => _position + offset,
                    SeekOrigin.End => _length + offset,
                    _ => throw new ArgumentOutOfRangeException(nameof(origin)),
                };
                _position = target;
                return _position;
            }

            public override void Flush() { }
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private sealed class CabEntryView : IArchiveEntry
        {
            public CabEntryView(CabFileData data, ArchiveFormatInfo format)
            {
                Data = data;
            }

            public CabFileData Data { get; }

            public string FullName => Data.Name;
            public string Name => Data.Name;
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
