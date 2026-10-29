using System;
using System.IO;
using GeneralZip.Cryptography;

namespace GeneralZip.Internal;

/// <summary>底层可寻址流上的只读窗口（限长、限起点）。</summary>
internal sealed class PartialStream : Stream
{
    private readonly Stream _inner;
    private readonly long _origin;
    private readonly long _length;
    private long _position;

    public PartialStream(Stream inner, long origin, long length)
    {
        if (!inner.CanSeek) throw new ArgumentException("PartialStream 需要可寻址的底层流", nameof(inner));
        _inner = inner;
        _origin = origin;
        _length = length;
        _position = 0;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set
        {
            if (value < 0 || value > _length) throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var remaining = _length - _position;
        if (remaining <= 0 || count <= 0) return 0;

        if (_inner.Position != _origin + _position)
        {
            _inner.Position = _origin + _position;
        }

        var toRead = (int)Math.Min(count, remaining);
        var n = _inner.Read(buffer, offset, toRead);
        if (n > 0) _position += n;
        return n;
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

        Position = target;
        return _position;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// 读取结束时校验 CRC-32 的透传流。
/// expectedCrc 为 null 时跳过校验（加密条目由 HMAC 保证完整性）。
/// </summary>
internal sealed class CrcCheckStream : Stream
{
    private readonly Stream _inner;
    private readonly uint? _expectedCrc;
    private readonly long? _knownLength;
    private readonly string _entryName;
    private readonly Crc32Hasher _hasher = new();
    private long _bytes;
    private bool _checked;

    public CrcCheckStream(Stream inner, uint? expectedCrc, string entryName, long? knownLength = null)
    {
        _inner = inner;
        _expectedCrc = expectedCrc;
        _entryName = entryName;
        _knownLength = knownLength;
    }

    public uint ActualCrc => _hasher.Value;

    public long BytesPassed => _bytes;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _knownLength
                                   ?? (_inner is { CanSeek: true } s ? s.Length : throw new NotSupportedException());
    public override long Position { get => _bytes; set => throw new NotSupportedException(); }
    public override bool CanTimeout => false;

    public override int Read(byte[] buffer, int offset, int count)
    {
        var n = _inner.Read(buffer, offset, count);
        if (n > 0)
        {
            _hasher.Update(buffer, offset, n);
            _bytes += n;
        }
        else if (!_checked)
        {
            _checked = true;
            if (_expectedCrc.HasValue && _hasher.Value != _expectedCrc.Value)
            {
                throw new ArchiveCorruptedException(
                    $"CRC 校验失败（期望 0x{_expectedCrc:X8}，实际 0x{_hasher.Value:X8}）：" +
                    "数据损坏，或口令错误（ZipCrypto 无法提前检测口令）", _entryName);
            }
        }

        return n;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
