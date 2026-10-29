using System;

namespace GeneralZip.Cryptography;

/// <summary>
/// SM3 密码杂凑算法（GB/T 32905-2016）纯 C# 实现。
/// 输出 256 位摘要；分组 512 位；无第三方依赖。
/// </summary>
public sealed class Sm3Digest
{
    private static readonly uint[] IV =
    {
        0x7380166Fu, 0x4914B2B9u, 0x172442D7u, 0xDA8A0600u,
        0xA96F30BCu, 0x163138AAu, 0xE38DEE4Du, 0xB0FB0E4Eu,
    };

    private const uint T0 = 0x79CC4519u;
    private const uint T1 = 0x7A879D8Au;

    private readonly uint[] _v = new uint[8];
    private readonly byte[] _buffer = new byte[64];
    private int _bufferLength;
    private long _totalBytes;
    private bool _finalized;

    public Sm3Digest()
    {
        Reset();
    }

    public void Reset()
    {
        Array.Copy(IV, _v, 8);
        _bufferLength = 0;
        _totalBytes = 0;
        _finalized = false;
    }

    public int DigestSize => 32;

    public void BlockUpdate(byte[] data, int offset, int count)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (_finalized) throw new InvalidOperationException("摘要已完成计算，请先 Reset");

        var pos = offset;
        var remaining = count;
        _totalBytes += count;

        if (_bufferLength > 0)
        {
            var take = Math.Min(64 - _bufferLength, remaining);
            Buffer.BlockCopy(data, pos, _buffer, _bufferLength, take);
            _bufferLength += take;
            pos += take;
            remaining -= take;

            if (_bufferLength == 64)
            {
                Compress(_buffer, 0);
                _bufferLength = 0;
            }
        }

        while (remaining >= 64)
        {
            Compress(data, pos);
            pos += 64;
            remaining -= 64;
        }

        if (remaining > 0)
        {
            Buffer.BlockCopy(data, pos, _buffer, 0, remaining);
            _bufferLength = remaining;
        }
    }

    public int DoFinal(byte[] output, int offset)
    {
        if (output == null) throw new ArgumentNullException(nameof(output));
        if (output.Length - offset < 32) throw new ArgumentException("输出缓冲区不足 32 字节", nameof(output));
        if (_finalized) throw new InvalidOperationException("摘要已完成计算，请先 Reset");

        var bitLength = _totalBytes * 8;

        // 填充：0x80 + 零 + 64 位大端长度
        var padLength = _bufferLength < 56 ? 56 - _bufferLength : 120 - _bufferLength;
        var pad = new byte[padLength + 8];
        pad[0] = 0x80;
        for (var i = 0; i < 8; i++)
        {
            pad[padLength + i] = (byte)(bitLength >> (56 - i * 8));
        }

        _totalBytes += padLength + 8; // 仅供内部一致性；DoFinal 后需 Reset
        BlockUpdate(pad, 0, pad.Length);
        System.Diagnostics.Debug.Assert(_bufferLength == 0);

        for (var i = 0; i < 8; i++)
        {
            output[offset + i * 4] = (byte)(_v[i] >> 24);
            output[offset + i * 4 + 1] = (byte)(_v[i] >> 16);
            output[offset + i * 4 + 2] = (byte)(_v[i] >> 8);
            output[offset + i * 4 + 3] = (byte)_v[i];
        }

        _finalized = true;
        return 32;
    }

    /// <summary>一次性计算。</summary>
    public static byte[] Hash(byte[] data)
    {
        var digest = new Sm3Digest();
        digest.BlockUpdate(data, 0, data.Length);
        var output = new byte[32];
        digest.DoFinal(output, 0);
        return output;
    }

    private void Compress(byte[] block, int offset)
    {
        var w = new uint[68];
        var wPrime = new uint[64];

        for (var i = 0; i < 16; i++)
        {
            w[i] = ((uint)block[offset + i * 4] << 24)
                   | ((uint)block[offset + i * 4 + 1] << 16)
                   | ((uint)block[offset + i * 4 + 2] << 8)
                   | block[offset + i * 4 + 3];
        }

        for (var j = 16; j < 68; j++)
        {
            var tmp = P1(w[j - 16] ^ w[j - 9] ^ Rotl(w[j - 3], 15));
            w[j] = tmp ^ Rotl(w[j - 13], 7) ^ w[j - 6];
        }

        for (var j = 0; j < 64; j++)
        {
            wPrime[j] = w[j] ^ w[j + 4];
        }

        var a = _v[0];
        var b = _v[1];
        var c = _v[2];
        var d = _v[3];
        var e = _v[4];
        var f = _v[5];
        var g = _v[6];
        var h = _v[7];

        for (var j = 0; j < 64; j++)
        {
            var t = j < 16 ? T0 : T1;
            var ss1 = Rotl(Rotl(a, 12) + e + Rotl(t, j), 7);
            var ss2 = ss1 ^ Rotl(a, 12);
            var tt1 = Ff(a, b, c, j) + d + ss2 + wPrime[j];
            var tt2 = Gg(e, f, g, j) + h + ss1 + w[j];
            d = c;
            c = Rotl(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = Rotl(f, 19);
            f = e;
            e = P0(tt2);
        }

        _v[0] ^= a;
        _v[1] ^= b;
        _v[2] ^= c;
        _v[3] ^= d;
        _v[4] ^= e;
        _v[5] ^= f;
        _v[6] ^= g;
        _v[7] ^= h;
    }

    private static uint Rotl(uint x, int n) => (x << n) | (x >> (32 - n));

    private static uint P0(uint x) => x ^ Rotl(x, 9) ^ Rotl(x, 17);

    private static uint P1(uint x) => x ^ Rotl(x, 15) ^ Rotl(x, 23);

    private static uint Ff(uint x, uint y, uint z, int j) => j < 16 ? x ^ y ^ z : (x & y) | (x & z) | (y & z);

    private static uint Gg(uint x, uint y, uint z, int j) => j < 16 ? x ^ y ^ z : (x & y) | (~x & z);
}
