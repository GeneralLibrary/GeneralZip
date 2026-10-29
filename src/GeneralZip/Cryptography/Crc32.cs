using System;
using System.IO;

namespace GeneralZip.Cryptography;

/// <summary>CRC-32（IEEE 802.3，多项式 0xEDB88320，ZIP/gzip 标准）。</summary>
public static class Crc32
{
    internal static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var c = i;
            for (var k = 0; k < 8; k++)
            {
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            }

            table[i] = c;
        }

        return table;
    }

    public const uint InitialValue = 0u;

    public static uint Compute(byte[] buffer, int offset, int count, uint seed = InitialValue)
    {
        var crc = seed ^ 0xFFFFFFFFu;
        for (var i = 0; i < count; i++)
        {
            crc = Table[(crc ^ buffer[offset + i]) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFu;
    }

    public static uint Compute(byte[] buffer) => Compute(buffer, 0, buffer.Length);
}

/// <summary>流式 CRC-32 计算器。</summary>
public sealed class Crc32Hasher
{
    private uint _crc = 0xFFFFFFFFu;
    private long _bytes;

    public void Update(byte[] buffer, int offset, int count)
    {
        for (var i = 0; i < count; i++)
        {
            _crc = Crc32.Table[(_crc ^ buffer[offset + i]) & 0xFF] ^ (_crc >> 8);
        }

        _bytes += count;
    }

    public uint Value => _crc ^ 0xFFFFFFFFu;

    public long BytesCount => _bytes;

    public void Reset()
    {
        _crc = 0xFFFFFFFFu;
        _bytes = 0;
    }
}

/// <summary>计算流经字节 CRC-32 的透传流（读/写两向均可用，供格式层校验）。</summary>
public sealed class Crc32Stream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly Crc32Hasher _hasher = new();

    public Crc32Stream(Stream inner, bool leaveOpen = true)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _leaveOpen = leaveOpen;
    }

    public uint Crc => _hasher.Value;

    public long BytesPassed => _hasher.BytesCount;

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => _inner.Length;
    public override long Position { get => _inner.Position; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var n = _inner.Read(buffer, offset, count);
        if (n > 0) _hasher.Update(buffer, offset, n);
        return n;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _hasher.Update(buffer, offset, count);
        _inner.Write(buffer, offset, count);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Flush() => _inner.Flush();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
