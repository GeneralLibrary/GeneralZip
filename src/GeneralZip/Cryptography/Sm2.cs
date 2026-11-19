using System;
using System.Numerics;

namespace GeneralZip.Cryptography;

/// <summary>SM2 椭圆曲线点（仿射坐标）。无穷远点以 IsInfinity 表示。</summary>
public struct Sm2Point
{
    public BigInteger X;
    public BigInteger Y;
    public bool IsInfinity;

    public static Sm2Point Infinity => new() { IsInfinity = true };
}

/// <summary>
/// SM2 椭圆曲线公钥密码（GB/T 32918 / GM/T 0003，256 位推荐曲线）。
/// 纯 C# 实现（BigInteger 仿射坐标），零第三方依赖。
/// <para>加密采用标准 ECIES 语义（KDF-SM3 掩码 + SM3 完整性），密文排列 C1‖C3‖C2（现行标准）。</para>
/// </summary>
public static class Sm2
{
    // ---------- 推荐曲线参数（GB/T 32918.5-2017） ----------

    private static readonly BigInteger P = FromHex(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
    private static readonly BigInteger A = FromHex(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"); // p - 3
    private static readonly BigInteger B = FromHex(
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
    private static readonly BigInteger N = FromHex(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
    private static readonly Sm2Point G = new()
    {
        X = FromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
        Y = FromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
    };

    /// <summary>基点 G 的阶 n。</summary>
    public static BigInteger Order => N;

    /// <summary>曲线点校验：y² ≡ x³ + ax + b (mod p)。</summary>
    public static bool IsOnCurve(BigInteger x, BigInteger y)
    {
        if (x < 0 || x >= P || y < 0 || y >= P)
        {
            return false;
        }

        var left = y * y % P;
        var right = (x * x % P * x + A * x + B) % P;
        return ((left - right) % P + P) % P == 0;
    }

    // ---------- 点运算 ----------

    public static Sm2Point Negate(Sm2Point p) => p.IsInfinity
        ? p
        : new Sm2Point { X = p.X, Y = (P - p.Y) % P };

    public static Sm2Point Add(Sm2Point p, Sm2Point q)
    {
        if (p.IsInfinity) return q;
        if (q.IsInfinity) return p;
        if (p.X == q.X)
        {
            if ((p.Y + q.Y) % P == 0)
            {
                return Sm2Point.Infinity;
            }

            return Double(p);
        }

        var lambda = (q.Y - p.Y) % P * ModInverse((q.X - p.X) % P) % P;
        lambda = ((lambda % P) + P) % P;
        var x3 = (lambda * lambda - p.X - q.X) % P;
        x3 = ((x3 % P) + P) % P;
        var y3 = (lambda * (p.X - x3) - p.Y) % P;
        y3 = ((y3 % P) + P) % P;
        return new Sm2Point { X = x3, Y = y3 };
    }

    public static Sm2Point Double(Sm2Point p)
    {
        if (p.IsInfinity || p.Y == 0)
        {
            return Sm2Point.Infinity;
        }

        // λ = (3x² + a) / (2y)
        var numerator = (3 * p.X % P * p.X + A) % P;
        numerator = ((numerator % P) + P) % P;
        var denominator = 2 * p.Y % P;
        var lambda = numerator * ModInverse(denominator) % P;
        lambda = ((lambda % P) + P) % P;
        var x3 = (lambda * lambda - 2 * p.X) % P;
        x3 = ((x3 % P) + P) % P;
        var y3 = (lambda * (p.X - x3) - p.Y) % P;
        y3 = ((y3 % P) + P) % P;
        return new Sm2Point { X = x3, Y = y3 };
    }

    /// <summary>标量乘法 [k]P（double-and-add，从高位向低位）。</summary>
    public static Sm2Point Multiply(BigInteger k, Sm2Point p)
    {
        if (p.IsInfinity || k == 0)
        {
            return Sm2Point.Infinity;
        }

        k %= N;
        if (k < 0)
        {
            k += N;
        }

        var result = Sm2Point.Infinity;
        var addend = p;
        while (k > 0)
        {
            if ((k & 1) == 1)
            {
                result = Add(result, addend);
            }

            addend = Double(addend);
            k >>= 1;
        }

        return result;
    }

    /// <summary>公钥 = [d]G。</summary>
    public static Sm2Point PublicKeyOf(BigInteger privateKey) => Multiply(privateKey, G);

    // ---------- ECIES（GB/T 32918.4，C1‖C3‖C2） ----------

    /// <summary>
    /// SM2 公钥加密。k 可注入（0 = 随机；非 0 用于确定性地测试/标准向量）。
    /// 输出：C1(65B 未压缩) ‖ C3(32B SM3) ‖ C2(klen)。
    /// </summary>
    public static byte[] Encrypt(byte[] plaintext, Sm2Point publicKey, BigInteger k = default)
    {
        if (plaintext.Length == 0)
        {
            throw new ArgumentException("Plaintext must not be empty", nameof(plaintext));
        }

        if (!IsOnCurve(publicKey.X, publicKey.Y))
        {
            throw new ArgumentException("Public key is not on the SM2 curve", nameof(publicKey));
        }

        // 随机 k ∈ [1, n-1]（确定性测试场景由调用方注入）
        if (k.IsZero)
        {
            k = RandomScalar();
        }

        var c1 = Multiply(k, G);
        if (c1.IsInfinity)
        {
            throw new InvalidOperationException("SM2 encryption: [k]G is the point at infinity; retry");
        }

        var shared = Multiply(k, publicKey);
        if (shared.IsInfinity)
        {
            throw new InvalidOperationException("SM2 encryption: [k]PB is the point at infinity; retry");
        }

        var x2 = To32Bytes(shared.X);
        var y2 = To32Bytes(shared.Y);

        var t = KdfSm3(x2, y2, plaintext.Length);
        var c2 = new byte[plaintext.Length];
        for (var i = 0; i < plaintext.Length; i++)
        {
            c2[i] = (byte)(plaintext[i] ^ t[i]);
        }

        var c3 = Sm3Digest.Hash(Concat3(x2, plaintext, y2));

        var output = new byte[65 + 32 + c2.Length];
        output[0] = 0x04;
        Write32(c1.X, output, 1);
        Write32(c1.Y, output, 33);
        Buffer.BlockCopy(c3, 0, output, 65, 32);
        Buffer.BlockCopy(c2, 0, output, 97, c2.Length);
        return output;
    }

    /// <summary>
    /// SM2 私钥解密。cipher = C1(65B) ‖ C3(32B) ‖ C2(klen)。
    /// </summary>
    /// <exception cref="ArgumentException">密文结构非法。</exception>
    /// <exception cref="InvalidOperationException">完整性校验失败（C3 不符，通常为密钥错误或密文被篡改）。</exception>
    public static byte[] Decrypt(byte[] cipher, BigInteger privateKey)
    {
        if (cipher.Length < 65 + 32 + 1)
        {
            throw new ArgumentException("SM2 ciphertext is too short", nameof(cipher));
        }

        if (cipher[0] != 0x04)
        {
            throw new ArgumentException("SM2 ciphertext C1 must be an uncompressed point (0x04 prefix)", nameof(cipher));
        }

        var x1 = Read32(cipher, 1);
        var y1 = Read32(cipher, 33);
        if (!IsOnCurve(x1, y1))
        {
            throw new ArgumentException("SM2 ciphertext C1 is not on the SM2 curve", nameof(cipher));
        }

        var c1 = new Sm2Point { X = x1, Y = y1 };
        var shared = Multiply(privateKey, c1);
        if (shared.IsInfinity)
        {
            throw new InvalidOperationException("SM2 decryption: [dB]C1 is the point at infinity");
        }

        var x2 = To32Bytes(shared.X);
        var y2 = To32Bytes(shared.Y);
        var klen = cipher.Length - 97;
        var t = KdfSm3(x2, y2, klen);

        var c2 = new byte[klen];
        Buffer.BlockCopy(cipher, 97, c2, 0, klen);
        var message = new byte[klen];
        for (var i = 0; i < klen; i++)
        {
            message[i] = (byte)(c2[i] ^ t[i]);
        }

        var expected = Sm3Digest.Hash(Concat3(x2, message, y2));
        var actual = new byte[32];
        Buffer.BlockCopy(cipher, 65, actual, 0, 32);
        if (!Kdf.FixedTimeEquals(expected, actual))
        {
            throw new InvalidOperationException("SM2 decryption failed: C3 integrity mismatch (wrong key or corrupted ciphertext)");
        }

        return message;
    }

    /// <summary>SM2 X9.63 风格 KDF：Ha_i = SM3(Z ‖ ct_i)，ct 为 32 位大端计数（从 1 起）。</summary>
    public static byte[] KdfSm3(byte[] z1, byte[] z2, int outputLength)
    {
        var output = new byte[outputLength];
        var hashLen = 32;
        var blocks = (outputLength + hashLen - 1) / hashLen;
        var pos = 0;
        var remaining = outputLength;
        for (uint ct = 1; ct <= blocks; ct++)
        {
            var input = new byte[z1.Length + z2.Length + 4];
            Buffer.BlockCopy(z1, 0, input, 0, z1.Length);
            Buffer.BlockCopy(z2, 0, input, z1.Length, z2.Length);
            var tail = input.Length - 4;
            input[tail] = (byte)(ct >> 24);
            input[tail + 1] = (byte)(ct >> 16);
            input[tail + 2] = (byte)(ct >> 8);
            input[tail + 3] = (byte)ct;

            var hash = Sm3Digest.Hash(input);
            var take = Math.Min(hashLen, remaining);
            Buffer.BlockCopy(hash, 0, output, pos, take);
            pos += take;
            remaining -= take;
        }

        return output;
    }

    // ---------- 密钥 ----------

    /// <summary>生成随机私钥 d ∈ [1, n-2]。</summary>
    public static BigInteger RandomScalar()
    {
        while (true)
        {
            var bytes = Kdf.RandomBytes(32);
            var d = FromUnsigned(bytes);
            if (d > 0 && d < N - 1)
            {
                return d;
            }
        }
    }

    /// <summary>公钥编码为 65 字节未压缩形式（0x04‖X‖Y）。</summary>
    public static byte[] EncodePoint(Sm2Point point)
    {
        if (point.IsInfinity)
        {
            throw new ArgumentException("Cannot encode the point at infinity");
        }

        var encoded = new byte[65];
        encoded[0] = 0x04;
        Write32(point.X, encoded, 1);
        Write32(point.Y, encoded, 33);
        return encoded;
    }

    /// <summary>解析 65 字节未压缩公钥（0x04 前缀），校验在曲线上。</summary>
    public static Sm2Point DecodePoint(byte[] encoded)
    {
        if (encoded == null || encoded.Length != 65 || encoded[0] != 0x04)
        {
            throw new ArgumentException("SM2 public key must be 65 bytes with 0x04 prefix", nameof(encoded));
        }

        var x = Read32(encoded, 1);
        var y = Read32(encoded, 33);
        if (!IsOnCurve(x, y))
        {
            throw new ArgumentException("SM2 public key point is not on the curve", nameof(encoded));
        }

        return new Sm2Point { X = x, Y = y };
    }

    // ---------- 内部 ----------

    private static BigInteger ModInverse(BigInteger value)
    {
        // p 为素数：逆元 = x^(p-2) mod p
        var x = ((value % P) + P) % P;
        if (x.IsZero)
        {
            throw new DivideByZeroException("SM2 modular inverse of zero");
        }

        return BigInteger.ModPow(x, P - 2, P);
    }

    internal static BigInteger FromHex(string hex) => BigInteger.Parse("0" + hex, System.Globalization.NumberStyles.HexNumber);

    /// <summary>32 字节大端无符号 → BigInteger（非负）。</summary>
    internal static BigInteger FromUnsigned(byte[] bigEndian32)
    {
        var little = new byte[bigEndian32.Length + 1]; // 末尾 0 保证非负
        for (var i = 0; i < bigEndian32.Length; i++)
        {
            little[i] = bigEndian32[bigEndian32.Length - 1 - i];
        }

        return new BigInteger(little);
    }

    private static byte[] To32Bytes(BigInteger value)
    {
        var bytes = value.ToByteArray(); // little-endian，可能带符号位
        var result = new byte[32];
        var take = Math.Min(bytes.Length, 32);
        Buffer.BlockCopy(bytes, 0, result, 0, take);
        Array.Reverse(result); // 大端
        return result;
    }

    /// <summary>BigInteger → 定长 32 字节大端（私钥/坐标序列化共用）。</summary>
    internal static byte[] To32BytesPrivate(BigInteger value) => To32Bytes(value);

    private static BigInteger Read32(byte[] buffer, int offset) => FromUnsigned(
        new[] { buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3],
                buffer[offset + 4], buffer[offset + 5], buffer[offset + 6], buffer[offset + 7],
                buffer[offset + 8], buffer[offset + 9], buffer[offset + 10], buffer[offset + 11],
                buffer[offset + 12], buffer[offset + 13], buffer[offset + 14], buffer[offset + 15],
                buffer[offset + 16], buffer[offset + 17], buffer[offset + 18], buffer[offset + 19],
                buffer[offset + 20], buffer[offset + 21], buffer[offset + 22], buffer[offset + 23],
                buffer[offset + 24], buffer[offset + 25], buffer[offset + 26], buffer[offset + 27],
                buffer[offset + 28], buffer[offset + 29], buffer[offset + 30], buffer[offset + 31] });

    private static void Write32(BigInteger value, byte[] buffer, int offset)
    {
        var be = To32Bytes(value);
        Buffer.BlockCopy(be, 0, buffer, offset, 32);
    }

    private static byte[] Concat3(byte[] a, byte[] b, byte[] c)
    {
        var result = new byte[a.Length + b.Length + c.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        Buffer.BlockCopy(c, 0, result, a.Length + b.Length, c.Length);
        return result;
    }
}

/// <summary>SM2 密钥对（公私钥；私钥为 BigInteger，公钥为 65 字节未压缩编码）。</summary>
public sealed class Sm2KeyPair
{
    private Sm2KeyPair(BigInteger privateKey, byte[] publicKey)
    {
        PrivateKey = privateKey;
        PublicKey = publicKey;
    }

    /// <summary>私钥标量 d。</summary>
    public BigInteger PrivateKey { get; }

    /// <summary>公钥 65 字节未压缩编码（0x04‖X‖Y）。</summary>
    public byte[] PublicKey { get; }

    /// <summary>生成随机密钥对。</summary>
    public static Sm2KeyPair Generate()
    {
        var d = Sm2.RandomScalar();
        return new Sm2KeyPair(d, Sm2.EncodePoint(Sm2.PublicKeyOf(d)));
    }

    /// <summary>从私钥恢复密钥对（私钥可为 32 字节大端 hex）。</summary>
    public static Sm2KeyPair FromPrivateKeyHex(string hex)
    {
        var d = Sm2.FromHex(hex.Trim());
        if (d <= 0 || d >= Sm2.Order - 1)
        {
            throw new ArgumentException("SM2 private key must be in [1, n-2]", nameof(hex));
        }

        return new Sm2KeyPair(d, Sm2.EncodePoint(Sm2.PublicKeyOf(d)));
    }

    /// <summary>私钥 hex（32 字节大端）。</summary>
    public string PrivateKeyHex => ToHex(Sm2.To32BytesPrivate(PrivateKey));

    /// <summary>公钥 hex（65 字节，含 04 前缀）。</summary>
    public string PublicKeyHex => ToHex(PublicKey);

    /// <summary>
    /// 解析公钥 hex："04‖X‖Y"（130 字符）或 "X‖Y"（128 字符，自动补 04 前缀）。
    /// 非法格式返回 null（供写路径参数校验使用）。
    /// </summary>
    public static byte[]? ParsePublicKeyHex(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
        {
            return null;
        }

        var clean = hex.Trim();
        if (clean.Length % 2 != 0 || !IsHex(clean))
        {
            return null;
        }

        byte[] bytes;
        try
        {
#if NETSTANDARD2_0
            bytes = new byte[clean.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(clean.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
            }
#else
            bytes = Convert.FromHexString(clean);
#endif
        }
        catch (FormatException)
        {
            return null;
        }

        if (bytes.Length == 64)
        {
            var full = new byte[65];
            full[0] = 0x04;
            Buffer.BlockCopy(bytes, 0, full, 1, 64);
            bytes = full;
        }

        if (bytes.Length != 65 || bytes[0] != 0x04)
        {
            return null;
        }

        try
        {
            Sm2.DecodePoint(bytes);
        }
        catch (ArgumentException)
        {
            return null;
        }

        return bytes;
    }

    private static bool IsHex(string s)
    {
        foreach (var c in s)
        {
            var ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    private static string ToHex(byte[] bytes)
    {
#if NETSTANDARD2_0
        var sb = new System.Text.StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            sb.Append(b.ToString("x2"));
        }

        return sb.ToString();
#else
        return Convert.ToHexString(bytes).ToLowerInvariant();
#endif
    }
}
