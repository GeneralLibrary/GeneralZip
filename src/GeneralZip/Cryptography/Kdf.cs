using System;
using System.Security.Cryptography;
using System.Text;

namespace GeneralZip.Cryptography;

/// <summary>增量式 MAC 抽象（屏蔽 .NET HMACSHA1 与自研 HMAC-SM3 的差异，供流式加密使用）。</summary>
public abstract class IncrementalMac
{
    public abstract int MacSize { get; }

    public abstract void Append(byte[] buffer, int offset, int count);

    public abstract byte[] Final();
}

/// <summary>HMAC-SHA1 增量计算（基于 .NET 内置 IncrementalHash）。</summary>
public sealed class HmacSha1Incremental : IncrementalMac
{
    private readonly IncrementalHash _inner;

    public HmacSha1Incremental(byte[] key)
    {
        _inner = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, key);
    }

    public override int MacSize => 20;

    public override void Append(byte[] buffer, int offset, int count) => _inner.AppendData(buffer, offset, count);

    public override byte[] Final() => _inner.GetHashAndReset();
}

/// <summary>HMAC-SM3 增量计算（自研，基于 <see cref="Sm3Digest"/>）。</summary>
public sealed class HmacSm3Incremental : IncrementalMac
{
    private readonly Sm3Digest _inner = new();
    private readonly byte[] _opad;
    private bool _innerDone;

    public HmacSm3Incremental(byte[] key)
    {
        // RFC 2104：K 长度补齐到 64 字节（SM3 分组），ipad/opad 异或
        var k = new byte[64];
        if (key.Length > 64)
        {
            var hashed = Sm3Digest.Hash(key);
            Buffer.BlockCopy(hashed, 0, k, 0, 32);
        }
        else
        {
            Buffer.BlockCopy(key, 0, k, 0, key.Length);
        }

        var ipad = new byte[64];
        _opad = new byte[64];
        for (var i = 0; i < 64; i++)
        {
            ipad[i] = (byte)(k[i] ^ 0x36);
            _opad[i] = (byte)(k[i] ^ 0x5C);
        }

        _inner.BlockUpdate(ipad, 0, 64);
    }

    public override int MacSize => 32;

    public override void Append(byte[] buffer, int offset, int count) => _inner.BlockUpdate(buffer, offset, count);

    public override byte[] Final()
    {
        if (_innerDone)
        {
            throw new InvalidOperationException("MAC already finalized");
        }

        _innerDone = true;
        var innerHash = new byte[32];
        _inner.DoFinal(innerHash, 0);

        var outer = new Sm3Digest();
        outer.BlockUpdate(_opad, 0, 64);
        outer.BlockUpdate(innerHash, 0, 32);
        var output = new byte[32];
        outer.DoFinal(output, 0);
        return output;
    }
}

/// <summary>
/// 密钥派生与 MAC 原语。零第三方依赖：
/// SHA1/PBKDF2-SHA1/AES 走 .NET 内置（微软官方），SM3/SM4/HMAC-SM3 为本组件纯 C# 实现。
/// </summary>
public static class Kdf
{
    /// <summary>PBKDF2-HMAC-SHA1（WinZip AES 规范要求；.NET 内置 Rfc2898DeriveBytes，默认 SHA1）。</summary>
    public static byte[] Pbkdf2Sha1(string password, byte[] salt, int iterations, int outputLength)
    {
        using var deriver = new Rfc2898DeriveBytes(
            Encoding.UTF8.GetBytes(password), salt, iterations);
        return deriver.GetBytes(outputLength);
    }

    /// <summary>PBKDF2-HMAC-SM3（国密 SM4-GM 方案，见 CRYPTO-SPEC.md；RFC 8018 标准循环）。</summary>
    public static byte[] Pbkdf2Sm3(string password, byte[] salt, int iterations, int outputLength)
    {
        return Pbkdf2HmacSm3(Encoding.UTF8.GetBytes(password), salt, iterations, outputLength);
    }

    public static byte[] Pbkdf2HmacSm3(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength < 1) throw new ArgumentOutOfRangeException(nameof(outputLength));

        var result = new byte[outputLength];
        var blocks = (outputLength + 31) / 32; // SM3 输出 32 字节

        for (uint blockIndex = 1; blockIndex <= blocks; blockIndex++)
        {
            // U1 = HMAC(P, S || INT(blockIndex))（大端 32 位）
            var saltBlock = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);
            saltBlock[salt.Length] = (byte)(blockIndex >> 24);
            saltBlock[salt.Length + 1] = (byte)(blockIndex >> 16);
            saltBlock[salt.Length + 2] = (byte)(blockIndex >> 8);
            saltBlock[salt.Length + 3] = (byte)blockIndex;

            var u = ComputeHmacSm3(password, saltBlock);
            var t = new byte[32];
            Buffer.BlockCopy(u, 0, t, 0, 32);

            for (var iter = 1; iter < iterations; iter++)
            {
                u = ComputeHmacSm3(password, u);
                for (var i = 0; i < 32; i++)
                {
                    t[i] ^= u[i];
                }
            }

            var offset = (int)((blockIndex - 1) * 32);
            var take = Math.Min(32, outputLength - offset);
            Buffer.BlockCopy(t, 0, result, offset, take);
        }

        return result;
    }

    /// <summary>HMAC-SM3 一次性计算。</summary>
    public static byte[] HmacSm3(byte[] key, params byte[][] parts)
    {
        var mac = new HmacSm3Incremental(key);
        foreach (var part in parts)
        {
            if (part != null && part.Length > 0)
            {
                mac.Append(part, 0, part.Length);
            }
        }

        return mac.Final();
    }

    private static byte[] ComputeHmacSm3(byte[] key, byte[] data)
    {
        var mac = new HmacSm3Incremental(key);
        mac.Append(data, 0, data.Length);
        return mac.Final();
    }

    /// <summary>增量式 HMAC-SHA1（供流式算法使用）。</summary>
    public static HmacSha1Incremental CreateIncrementalHmacSha1(byte[] key) => new(key);

    /// <summary>增量式 HMAC-SM3（供流式算法使用）。</summary>
    public static HmacSm3Incremental CreateIncrementalHmacSm3(byte[] key) => new(key);

    /// <summary>CSPRNG 填充。</summary>
    public static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
#if NETSTANDARD2_0
        using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
        {
            rng.GetBytes(bytes);
        }
#else
        RandomNumberGenerator.Fill(bytes);
#endif
        return bytes;
    }

    /// <summary>常数时间比较（比较前 length 字节）。</summary>
    public static bool FixedTimeEquals(byte[] a, byte[] b, int length)
    {
        if (a == null || b == null || a.Length < length || b.Length < length) return false;
#if NETSTANDARD2_0
        var diff = 0;
        for (var i = 0; i < length; i++)
        {
            diff |= a[i] ^ b[i];
        }

        return diff == 0;
#else
        return CryptographicOperations.FixedTimeEquals(a.AsSpan(0, length), b.AsSpan(0, length));
#endif
    }

    /// <summary>常数时间字节数组比较。</summary>
    public static bool FixedTimeEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        return FixedTimeEquals(a, b, a.Length);
    }

    /// <summary>清零敏感字节区。</summary>
    public static void Zero(byte[]? buffer)
    {
        if (buffer != null)
        {
            Array.Clear(buffer, 0, buffer.Length);
        }
    }
}
