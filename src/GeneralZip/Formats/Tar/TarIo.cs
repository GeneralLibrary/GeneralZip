using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace GeneralZip.Formats.Tar;

/// <summary>tar 条目头信息（ustar 解析结果）。</summary>
internal sealed class TarHeaderInfo
{
    public string Name { get; set; } = string.Empty;

    public long Size { get; set; }

    public bool IsDirectory { get; set; }

    public DateTimeOffset ModTime { get; set; } = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public int Mode { get; set; } = 420; // 0644

    public byte TypeFlag { get; set; }
}

/// <summary>ustar 魔数辅助。</summary>
internal static class TarIo
{
    /// <summary>检查前部缓冲偏移 257 处的 "ustar" 魔数（需 ≥262 字节）。</summary>
    public static bool HasUstarMagic(byte[] buf, int len)
    {
        if (len < 262) return false;
        return buf[257] == (byte)'u' && buf[258] == (byte)'s' && buf[259] == (byte)'t'
               && buf[260] == (byte)'a' && buf[261] == (byte)'r';
    }
}

/// <summary>
/// ustar/GNU tar 流式读取器（本组件自研实现，无第三方依赖）。
/// 支持：普通文件 / 目录、ustar prefix 字段、GNU 'L' 长名称扩展。
/// 游标语义：GetNextEntry 自动跳过上一条目数据；当前条目数据经
/// <see cref="ReadCurrentEntryData"/> 顺序读取，完成后调用 <see cref="FinishCurrentEntry"/>。
/// </summary>
internal sealed class TarStreamReader : IDisposable
{
    private readonly Stream _stream;
    private readonly Encoding _encoding;
    private string? _pendingLongName;
    private bool _eof;
    private bool _haveCurrent;
    private long _dataRemaining;
    private long _padRemaining;
    private readonly byte[] _skipBuffer = new byte[512];

    public TarStreamReader(Stream stream, Encoding encoding)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _encoding = encoding ?? throw new ArgumentNullException(nameof(encoding));
    }

    /// <summary>顺序模式下已返回的条目数（供顺序定位游标使用）。</summary>
    public int EntriesReturned { get; private set; }

    /// <summary>读取下一个条目头；流结束返回 null。</summary>
    public TarHeaderInfo? GetNextEntry()
    {
        if (_eof) return null;

        if (_haveCurrent)
        {
            SkipFully(_dataRemaining);
            SkipFully(_padRemaining);
            _haveCurrent = false;
        }

        var pendingName = _pendingLongName;
        _pendingLongName = null;

        var header = ReadHeaderBlock();
        if (header == null)
        {
            _eof = true;
            return null;
        }

        if (pendingName != null)
        {
            header.Name = pendingName;
        }

        if (header.TypeFlag == (byte)'L') // GNU 长名称：数据段为下一条目真实名称
        {
            var longNameBytes = ReadDataBytes(header.Size);
            _pendingLongName = _encoding.GetString(longNameBytes).TrimEnd('\0');
            return GetNextEntry();
        }

        if (header.IsDirectory && !header.Name.EndsWith("/", StringComparison.Ordinal))
        {
            header.Name += "/";
        }

        _haveCurrent = true;
        _dataRemaining = header.Size;
        _padRemaining = (512 - (header.Size % 512)) % 512;
        EntriesReturned++;
        return header;
    }

    /// <summary>从当前条目数据段顺序读取（须紧跟 GetNextEntry 之后）。</summary>
    public int ReadCurrentEntryData(byte[] buffer, int offset, int count)
    {
        if (!_haveCurrent)
        {
            throw new InvalidOperationException("当前无活动条目");
        }

        var toRead = (int)Math.Min(count, _dataRemaining);
        if (toRead <= 0) return 0;

        var total = 0;
        while (total < toRead)
        {
            var n = _stream.Read(buffer, offset + total, toRead - total);
            if (n <= 0)
            {
                throw new ArchiveCorruptedException("TAR 条目数据意外截断");
            }

            total += n;
        }

        _dataRemaining -= total;
        return total;
    }

    /// <summary>结束当前条目：跳过剩余数据与对齐填充。</summary>
    public void FinishCurrentEntry()
    {
        if (!_haveCurrent) return;
        SkipFully(_dataRemaining);
        SkipFully(_padRemaining);
        _dataRemaining = 0;
        _padRemaining = 0;
        _haveCurrent = false;
    }

    /// <summary>顺序模式下跳过指定条目的数据（按头中记录的大小）。</summary>
    public void SkipCurrentEntryData(long size) => SkipFully(size);

    private void SkipFully(long count)
    {
        var remaining = count;
        while (remaining > 0)
        {
            var n = _stream.Read(_skipBuffer, 0, (int)Math.Min(_skipBuffer.Length, remaining));
            if (n <= 0)
            {
                throw new ArchiveCorruptedException("TAR 数据意外截断");
            }

            remaining -= n;
        }
    }

    private byte[] ReadDataBytes(long size)
    {
        var data = new byte[size];
        var total = 0;
        while (total < size)
        {
            var n = _stream.Read(data, total, (int)Math.Min(size - total, int.MaxValue));
            if (n <= 0)
            {
                throw new ArchiveCorruptedException("TAR 条目数据意外截断");
            }

            total += n;
        }

        SkipFully((512 - (size % 512)) % 512);
        return data;
    }

    private TarHeaderInfo? ReadHeaderBlock()
    {
        var header = new byte[512];
        if (!ReadExactly(header))
        {
            return null; // 流自然结束
        }

        // 全零块 = 结束标记（消费第二个零块）
        if (IsZeroBlock(header))
        {
            ReadExactly(header);
            _eof = true;
            return null;
        }

        if (header[257] != (byte)'u' || header[258] != (byte)'s' || header[259] != (byte)'t'
            || header[260] != (byte)'a' || header[261] != (byte)'r')
        {
            throw new ArchiveCorruptedException("TAR 头部魔数错误（非 ustar 格式）");
        }

        var info = new TarHeaderInfo
        {
            Name = ReadName(header),
            Mode = (int)ParseOctal(header, 100, 8, 420), // 0644 默认
            Size = ParseOctal(header, 124, 12, 0),
            TypeFlag = header[156],
        };

        var mtime = ParseOctal(header, 136, 12, 0);
        info.ModTime = DateTimeOffset.FromUnixTimeSeconds((long)mtime);

        var typeFlag = header[156];
        if (typeFlag == 0 || typeFlag == (byte)'0')
        {
            info.IsDirectory = info.Name.EndsWith("/", StringComparison.Ordinal);
        }
        else if (typeFlag == (byte)'5')
        {
            info.IsDirectory = true;
        }
        else if (typeFlag is (byte)'1' or (byte)'2' or (byte)'3' or (byte)'4' or (byte)'6')
        {
            throw new UnsupportedFormatException($"不支持的 TAR 条目类型 '{(char)typeFlag}'（链接/设备文件）");
        }

        // 校验和：头 148 字节 + 8 空格 + 后 356 字节
        var storedChecksum = ParseOctal(header, 148, 8, -1);
        var computed = 0L;
        for (var i = 0; i < 512; i++)
        {
            computed += i >= 148 && i < 156 ? 32 : header[i];
        }

        if (storedChecksum >= 0 && storedChecksum != computed)
        {
            throw new ArchiveCorruptedException($"TAR 头部校验和不匹配（存储 {storedChecksum}，计算 {computed}）");
        }

        return info;
    }

    private static bool IsZeroBlock(byte[] block)
    {
        foreach (var b in block)
        {
            if (b != 0) return false;
        }

        return true;
    }

    private string ReadName(byte[] header)
    {
        var name = ReadField(header, 0, 100);
        var prefix = ReadField(header, 345, 155);

        var combined = prefix.Length > 0 ? prefix + "/" + name : name;
        return combined.Replace('\\', '/');
    }

    private string ReadField(byte[] header, int offset, int length)
    {
        var end = offset;
        var limit = offset + length;
        while (end < limit && header[end] != 0)
        {
            end++;
        }

        return _encoding.GetString(header, offset, end - offset);
    }

    private static long ParseOctal(byte[] header, int offset, int length, long fallback)
    {
        // GNU base-256（高位 0x80）大数值编码
        if ((header[offset] & 0x80) != 0)
        {
            long raw = header[offset] & 0x7F;
            for (var i = 1; i < length; i++)
            {
                raw = (raw << 8) | header[offset + i];
            }

            return raw;
        }

        var text = Encoding.ASCII.GetString(header, offset, length).Trim('\0', ' ');
        if (text.Length == 0)
        {
            return fallback;
        }

        // TAR 数值字段为八进制 ASCII
        try
        {
            return Convert.ToInt64(text, 8);
        }
        catch (FormatException)
        {
            return fallback;
        }
    }

    private bool ReadExactly(byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = _stream.Read(buffer, total, buffer.Length - total);
            if (n <= 0)
            {
                return total == 0; // 恰好读到流尾视为自然结束；半块视为损坏
            }

            total += n;
        }

        return true;
    }

    public void Dispose()
    {
    }
}

/// <summary>ustar 流式写入器（本组件自研实现，无第三方依赖）。</summary>
internal sealed class TarStreamWriter : IDisposable
{
    private readonly Stream _stream;
    private readonly Encoding _encoding;
    private long _entrySize;
    private long _remaining;
    private bool _entryOpen;
    private bool _finished;

    private static readonly byte[] ZeroBlock = new byte[512];

    public TarStreamWriter(Stream stream, Encoding encoding)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _encoding = encoding ?? throw new ArgumentNullException(nameof(encoding));
    }

    /// <summary>写入条目头。size 为随后写入的数据字节数（目录为 0）。</summary>
    public void PutNextEntry(string name, long size, DateTimeOffset modTime, int mode, bool isDirectory)
    {
        if (_entryOpen)
        {
            throw new InvalidOperationException("上一条目尚未关闭（CloseEntry）");
        }

        var header = BuildHeader(name, size, modTime, mode, isDirectory ? (byte)'5' : (byte)'0');
        _stream.Write(header, 0, header.Length);
        _entrySize = size;
        _remaining = size;
        _entryOpen = true;
    }

    public void Write(byte[] buffer, int offset, int count)
    {
        if (!_entryOpen)
        {
            throw new InvalidOperationException("未打开条目");
        }

        _stream.Write(buffer, offset, count);
        _remaining -= count;
    }

    public void CloseEntry()
    {
        if (!_entryOpen) return;
        _entryOpen = false;

        // 填充按条目声明的原始大小计算（写入后 _remaining 已归零）
        var padding = (512 - (_entrySize % 512)) % 512;
        if (padding > 0)
        {
            _stream.Write(ZeroBlock, 0, (int)padding);
        }

        _remaining = 0;
    }

    /// <summary>写两个全零结束块并刷新。</summary>
    public void Finish()
    {
        if (_finished) return;
        _finished = true;

        if (_entryOpen)
        {
            CloseEntry();
        }

        _stream.Write(ZeroBlock, 0, 512);
        _stream.Write(ZeroBlock, 0, 512);
        _stream.Flush();
    }

    internal byte[] BuildHeader(string name, long size, DateTimeOffset modTime, int mode, byte typeFlag)
    {
        var header = new byte[512];
        var finalName = name.Replace('\\', '/').TrimStart('/');
        var prefix = string.Empty;

        var nameBytes = _encoding.GetBytes(finalName);
        if (nameBytes.Length > 100)
        {
            // ustar prefix 拆分：在 '/' 处分割，prefix ≤155 且剩余 ≤100
            var split = finalName.LastIndexOf('/', Math.Min(finalName.Length - 2, 154));
            if (split < 1 || finalName.Length - split - 1 > 100)
            {
                throw new NotSupportedException("条目名过长且无法拆分为 ustar prefix（>255 字节）");
            }

            prefix = finalName.Substring(0, split);
            finalName = finalName.Substring(split + 1);
        }

        // ustar 名称字段为原始字节（UTF-8 等多字节名称经 prefix 拆分后按字节写入，
        // 不能用 ASCII 转写，否则非 ASCII 名称损坏且长度错位）
        WriteNameBytes(header, 0, 100, finalName, _encoding);
        WriteOctal(header, 100, 8, mode);
        WriteOctal(header, 108, 8, 0); // uid
        WriteOctal(header, 116, 8, 0); // gid
        WriteOctal(header, 124, 12, size);
        WriteOctal(header, 136, 12, (long)modTime.ToUnixTimeSeconds());

        // 校验和字段先填空格
        for (var i = 148; i < 156; i++)
        {
            header[i] = 0x20;
        }

        header[156] = typeFlag;
        WriteField(header, 257, 6, "ustar");
        WriteField(header, 263, 2, "00");
        WriteField(header, 265, 32, "GeneralZip");
        WriteField(header, 297, 32, "GeneralZip");
        if (prefix.Length > 0)
        {
            WriteNameBytes(header, 345, 155, prefix, _encoding);
        }

        var checksum = 0L;
        for (var i = 0; i < 512; i++)
        {
            checksum += header[i];
        }

        WriteOctal(header, 148, 7, checksum);
        header[155] = 0x20; // 校验和字段末字节规范为空格

        return header;
    }

    /// <summary>名称/prefix 字段按指定编码写入原始字节（超长抛出，由调用方先做 prefix 拆分）。</summary>
    private void WriteNameBytes(byte[] header, int offset, int length, string value, Encoding encoding)
    {
        var bytes = encoding.GetBytes(value);
        if (bytes.Length > length)
        {
            throw new ArgumentException($"TAR 名称字段超长（{bytes.Length} > {length}）");
        }

        Buffer.BlockCopy(bytes, 0, header, offset, bytes.Length);
    }

    /// <summary>写入 ASCII 元数据字段（uname/gname/magic/version 等）。</summary>
    private static void WriteField(byte[] header, int offset, int length, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        if (bytes.Length > length)
        {
            throw new ArgumentException($"TAR 字段超长（{bytes.Length} > {length}）");
        }

        Buffer.BlockCopy(bytes, 0, header, offset, bytes.Length);
    }

    /// <summary>写入八进制数值字段（length 含结尾 NUL）。</summary>
    private static void WriteOctal(byte[] header, int offset, int length, long value)
    {
        // 长度含结尾 NUL：有效数字位数 = length - 1
        var text = Convert.ToString(value, 8);
        if (text.Length > length - 1)
        {
            throw new ArgumentException($"TAR 八进制字段溢出（{value} 超出 {length} 字节）");
        }

        var pad = length - 1 - text.Length;
        for (var i = 0; i < pad; i++)
        {
            header[offset + i] = (byte)'0';
        }

        for (var i = 0; i < text.Length; i++)
        {
            header[offset + pad + i] = (byte)text[i];
        }

        header[offset + length - 1] = 0;
    }

    public void Dispose()
    {
        if (!_finished)
        {
            try
            {
                Finish();
            }
            catch
            {
                // 收尾失败不遮蔽主异常
            }
        }
    }
}
