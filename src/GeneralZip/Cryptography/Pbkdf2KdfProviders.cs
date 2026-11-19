using System;
using System.Security.Cryptography;
using System.Text;
using GeneralZip.Abstractions;

namespace GeneralZip.Cryptography;

/// <summary>
/// PBKDF2-HMAC-SM3（国密方案，RFC 8018 标准循环）。SM4-GM 容器规范 KdfId = 1（默认）。
/// </summary>
public sealed class Pbkdf2Sm3KdfProvider : IKdfProvider
{
    public byte SpecId => 1;

    public string KdfId => "SM3-PBKDF2";

    /// <summary>规范默认迭代次数。</summary>
    public const int DefaultIterations = 10_000;

    public byte[] Derive(string password, byte[] salt, int iterations, int outputLength)
        => Kdf.Pbkdf2Sm3(password, salt, iterations <= 0 ? DefaultIterations : iterations, outputLength);
}

/// <summary>
/// PBKDF2-HMAC-SHA256（国际方案）。SM4-GM 容器规范 KdfId = 2。
/// 迭代语义与 SHA1 版本一致；netstandard2.0 下用 IncrementalHash 手写 RFC 8018 循环。
/// </summary>
public sealed class Pbkdf2Sha256KdfProvider : IKdfProvider
{
    public byte SpecId => 2;

    public string KdfId => "PBKDF2-SHA256";

    /// <summary>规范默认迭代次数。</summary>
    public const int DefaultIterations = 10_000;

    public byte[] Derive(string password, byte[] salt, int iterations, int outputLength)
        => Pbkdf2HmacSha256(Encoding.UTF8.GetBytes(password), salt, iterations <= 0 ? DefaultIterations : iterations, outputLength);

    internal static byte[] Pbkdf2HmacSha256(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength < 1) throw new ArgumentOutOfRangeException(nameof(outputLength));

        var result = new byte[outputLength];
        var blocks = (outputLength + 31) / 32;

        for (uint blockIndex = 1; blockIndex <= blocks; blockIndex++)
        {
            var saltBlock = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);
            saltBlock[salt.Length] = (byte)(blockIndex >> 24);
            saltBlock[salt.Length + 1] = (byte)(blockIndex >> 16);
            saltBlock[salt.Length + 2] = (byte)(blockIndex >> 8);
            saltBlock[salt.Length + 3] = (byte)blockIndex;

            var u = ComputeHmacSha256(password, saltBlock);
            var t = new byte[32];
            Buffer.BlockCopy(u, 0, t, 0, 32);

            for (var iter = 1; iter < iterations; iter++)
            {
                u = ComputeHmacSha256(password, u);
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

    private static byte[] ComputeHmacSha256(byte[] key, byte[] data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }
}
