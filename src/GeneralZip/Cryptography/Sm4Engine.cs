using System;

namespace GeneralZip.Cryptography;

/// <summary>
/// SM4 分组密码算法（GB/T 32907-2016）纯 C# 实现。
/// 128 位分组 / 128 位密钥、32 轮非线性迭代；无第三方依赖。
/// </summary>
public sealed class Sm4Engine
{
    // S 盒（GB/T 32907-2016 附录 A / IETF draft-ribose-cfrg-sm4）
    private static readonly byte[] Sbox =
    {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
    };

    private static readonly uint[] Fk = { 0xA3B1BAC6u, 0x56AA3350u, 0x677D9197u, 0xB27022DCu };

    private static readonly uint[] Ck =
    {
        0x00070E15u, 0x1C232A31u, 0x383F464Du, 0x545B6269u,
        0x70777E85u, 0x8C939AA1u, 0xA8AFB6BDu, 0xC4CBD2D9u,
        0xE0E7EEF5u, 0xFC030A11u, 0x181F262Du, 0x343B4249u,
        0x50575E65u, 0x6C737A81u, 0x888F969Du, 0xA4ABB2B9u,
        0xC0C7CED5u, 0xDCE3EAF1u, 0xF8FF060Du, 0x141B2229u,
        0x30373E45u, 0x4C535A61u, 0x686F767Du, 0x848B9299u,
        0xA0A7AEB5u, 0xBCC3CAD1u, 0xD8DFE6EDu, 0xF4FB0209u,
        0x10171E25u, 0x2C333A41u, 0x484F565Du, 0x646B7279u,
    };

    private readonly uint[] _roundKeys = new uint[32];

    public int BlockSize => 16;

    /// <summary>装入 16 字节密钥并展开轮密钥。</summary>
    public void Init(bool forEncryption, byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 16) throw new ArgumentException("SM4 密钥必须为 16 字节", nameof(key));

        var mk = new uint[4];
        for (var i = 0; i < 4; i++)
        {
            mk[i] = ((uint)key[i * 4] << 24) | ((uint)key[i * 4 + 1] << 16)
                    | ((uint)key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        var k = new uint[36];
        for (var i = 0; i < 4; i++)
        {
            k[i] = mk[i] ^ Fk[i];
        }

        for (var i = 0; i < 32; i++)
        {
            k[i + 4] = k[i] ^ TPrime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ Ck[i]);
            _roundKeys[i] = k[i + 4];
        }

        // 解密使用反序轮密钥（存储时直接反序，ProcessBlock 无需分支）
        if (!forEncryption)
        {
            Array.Reverse(_roundKeys);
        }
    }

    /// <summary>加/解密单个 16 字节分组。</summary>
    public void ProcessBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
    {
        var x0 = ((uint)input[inputOffset] << 24) | ((uint)input[inputOffset + 1] << 16)
                 | ((uint)input[inputOffset + 2] << 8) | input[inputOffset + 3];
        var x1 = ((uint)input[inputOffset + 4] << 24) | ((uint)input[inputOffset + 5] << 16)
                 | ((uint)input[inputOffset + 6] << 8) | input[inputOffset + 7];
        var x2 = ((uint)input[inputOffset + 8] << 24) | ((uint)input[inputOffset + 9] << 16)
                 | ((uint)input[inputOffset + 10] << 8) | input[inputOffset + 11];
        var x3 = ((uint)input[inputOffset + 12] << 24) | ((uint)input[inputOffset + 13] << 16)
                 | ((uint)input[inputOffset + 14] << 8) | input[inputOffset + 15];

        for (var i = 0; i < 32; i++)
        {
            var tmp = x1 ^ x2 ^ x3 ^ _roundKeys[i];
            x0 = x0 ^ T(tmp);
            (x0, x1, x2, x3) = (x1, x2, x3, x0);
        }

        // 反序变换 R：输出 (X35, X34, X33, X32)
        var r0 = x3;
        var r1 = x2;
        var r2 = x1;
        var r3 = x0;

        output[outputOffset] = (byte)(r0 >> 24);
        output[outputOffset + 1] = (byte)(r0 >> 16);
        output[outputOffset + 2] = (byte)(r0 >> 8);
        output[outputOffset + 3] = (byte)r0;
        output[outputOffset + 4] = (byte)(r1 >> 24);
        output[outputOffset + 5] = (byte)(r1 >> 16);
        output[outputOffset + 6] = (byte)(r1 >> 8);
        output[outputOffset + 7] = (byte)r1;
        output[outputOffset + 8] = (byte)(r2 >> 24);
        output[outputOffset + 9] = (byte)(r2 >> 16);
        output[outputOffset + 10] = (byte)(r2 >> 8);
        output[outputOffset + 11] = (byte)r2;
        output[outputOffset + 12] = (byte)(r3 >> 24);
        output[outputOffset + 13] = (byte)(r3 >> 16);
        output[outputOffset + 14] = (byte)(r3 >> 8);
        output[outputOffset + 15] = (byte)r3;
    }

    /// <summary>加密变换 T：τ（S 盒逐字节）+ L。</summary>
    private static uint T(uint x)
    {
        var b = Tau(x);
        return b ^ Rotl(b, 2) ^ Rotl(b, 10) ^ Rotl(b, 18) ^ Rotl(b, 24);
    }

    /// <summary>密钥扩展变换 T'：τ + R。</summary>
    private static uint TPrime(uint x)
    {
        var b = Tau(x);
        return b ^ Rotl(b, 13) ^ Rotl(b, 23);
    }

    private static uint Tau(uint x)
    {
        return ((uint)Sbox[(x >> 24) & 0xFF] << 24)
               | ((uint)Sbox[(x >> 16) & 0xFF] << 16)
               | ((uint)Sbox[(x >> 8) & 0xFF] << 8)
               | Sbox[x & 0xFF];
    }

    private static uint Rotl(uint x, int n) => (x << n) | (x >> (32 - n));
}
