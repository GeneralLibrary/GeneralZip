using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Cryptography;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>
/// SM2（GB/T 32918）与 SM2-GM 信封加密测试。
/// 曲线参数与 ECIES 语义经独立实现（Python gmssl）双向交叉验证；
/// 下方 anchor 向量为 gmssl 产出的真实密文，锁定互通性。
/// </summary>
public class Sm2Tests
{
    private static bool HasCore => global::GeneralZip.Formats.Codecs.NativeCodecRouter.IsCoreAvailable();
    private static bool SkipIfNoCore()
    {
        if (HasCore) return false;
        Assert.True(true, "SKIPPED: native core not loaded");
        return true;
    }

    // gmssl（Python 独立实现）加密的锚点密文（C1‖C3‖C2，补 04 前缀后可解）
    private const string AnchorPrivateKeyHex =
        "8c8b89335e42c636156ee63fd0c7afa0e1c1845b4a86feea77daef214b2b6cd8";
    private const string AnchorCipherHexNo04 =
        "28fb184b5a7a49cf8839fec53aba1d9987f8e9f8b540db4261d47a63e279950f26e590f7bd8a2178fd7983fef3da653d811b07058b1eb416debb0566085406773d6ade8f26c3200fcbedbe55ec731133b78cc8d437fa3582b9d24f6a50e1bfd9fb6e2c82fa8f58846a77b8c8fd6ca1cd4a9fd0a07e8d4c7c7108b2a96b14212382d8be6bd67f7ebd94a15f50600dc47d61";
    private const string AnchorPlainHex =
        "676d73736c20696e7465726f7020616e63686f723a2047656e6572616c5a697020534d3220e9aa8ce8af81e59091e9878f";

    [Fact]
    public void AnchorVector_GmsslCiphertextDecrypts()
    {
        if (SkipIfNoCore()) return;
        var d = Sm2KeyPair.FromPrivateKeyHex(AnchorPrivateKeyHex);
        var cipher = Convert.FromHexString("04" + AnchorCipherHexNo04);
        var plain = Sm2.Decrypt(cipher, d.PrivateKey);
        Assert.Equal(Convert.FromHexString(AnchorPlainHex), plain);
    }

    [Fact]
    public void KeyPair_RestoreRoundtrip()
    {
        var kp = Sm2KeyPair.Generate();
        var restored = Sm2KeyPair.FromPrivateKeyHex(kp.PrivateKeyHex);
        Assert.Equal(kp.PublicKeyHex, restored.PublicKeyHex);
    }

    [Fact]
    public void EncryptDecrypt_RoundtripWithFixedK()
    {
        if (SkipIfNoCore()) return;
        var kp = Sm2KeyPair.Generate();
        var pub = Sm2.DecodePoint(kp.PublicKey);
        var message = Encoding.UTF8.GetBytes("SM2 roundtrip 中文 0123456789");

        var cipher = Sm2.Encrypt(message, pub, 1234567);
        // 同 k 确定性
        var cipher2 = Sm2.Encrypt(message, pub, 1234567);
        Assert.Equal(cipher, cipher2);

        var plain = Sm2.Decrypt(cipher, kp.PrivateKey);
        Assert.Equal(message, plain);
    }

    [Fact]
    public void Decrypt_TamperedC3Fails()
    {
        if (SkipIfNoCore()) return;
        var kp = Sm2KeyPair.Generate();
        var message = Encoding.UTF8.GetBytes("tamper me");
        var cipher = Sm2.Encrypt(message, Sm2.DecodePoint(kp.PublicKey));
        cipher[65] ^= 0x01; // 破坏 C3 第一字节
        Assert.Throws<InvalidOperationException>(() => Sm2.Decrypt(cipher, kp.PrivateKey));
    }

    [Fact]
    public void Decrypt_WrongKeyFails()
    {
        if (SkipIfNoCore()) return;
        var kp = Sm2KeyPair.Generate();
        var other = Sm2KeyPair.Generate();
        var cipher = Sm2.Encrypt(Encoding.UTF8.GetBytes("for kp only"), Sm2.DecodePoint(kp.PublicKey));
        Assert.Throws<InvalidOperationException>(() => Sm2.Decrypt(cipher, other.PrivateKey));
    }

    [Fact]
    public void PointOps_InfinityAndNegation()
    {
        // [n]G = 无穷远点
        var inf = Sm2.Multiply(Sm2.Order, new Sm2Point { X = BigInteger.Parse("0" + "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", System.Globalization.NumberStyles.HexNumber), Y = BigInteger.Parse("0" + "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", System.Globalization.NumberStyles.HexNumber) });
        Assert.True(inf.IsInfinity);

        // P + (-P) = 无穷远
        var kp = Sm2KeyPair.Generate();
        var p = Sm2.DecodePoint(kp.PublicKey);
        var sum = Sm2.Add(p, Sm2.Negate(p));
        Assert.True(sum.IsInfinity);

        // [2]G 不等于 G；[1]G = G
        var g = Sm2.DecodePoint(Convert.FromHexString(
            "0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7" +
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"));
        Assert.Equal(g.X, Sm2.Multiply(1, g).X);
        Assert.NotEqual(g.X, Sm2.Double(g).X);
    }

    [Fact]
    public void ParsePublicKeyHex_Accepts04PrefixAndBare()
    {
        var kp = Sm2KeyPair.Generate();
        var with04 = kp.PublicKeyHex;
        var bare = with04[2..];

        Assert.Equal(kp.PublicKey, Sm2KeyPair.ParsePublicKeyHex(with04));
        Assert.Equal(kp.PublicKey, Sm2KeyPair.ParsePublicKeyHex(bare));
        Assert.Null(Sm2KeyPair.ParsePublicKeyHex("zz"));
        Assert.Null(Sm2KeyPair.ParsePublicKeyHex("04"));
    }
}

/// <summary>SM2-GM 信封加密（ZIP extra field 0x4D54）与 KDF 可插拔测试。</summary>
public class Sm2GmAndKdfTests : IDisposable
{
    private static bool HasCore => global::GeneralZip.Formats.Codecs.NativeCodecRouter.IsCoreAvailable();
    private static bool SkipIfNoCore()
    {
        if (HasCore) return false;
        Assert.True(true, "SKIPPED: native core not loaded");
        return true;
    }

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");

    public Sm2GmAndKdfTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void Sm2Gm_EnvelopeRoundtrip()
    {
        if (SkipIfNoCore()) return;
        var zip = Path.Combine(_dir, "sm2.zip");
        var kp = Sm2KeyPair.Generate();
        var payload = Encoding.UTF8.GetBytes("SM2-GM envelope 中文 payload");

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
        {
            o.EncryptionAlgorithm = "SM2-GM";
            o.RecipientPublicKey = kp.PublicKeyHex;
        }))
        {
            w.AddStream("secret.txt", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip, o => o.Password = kp.PrivateKeyHex);
        Assert.True(r.IsEncrypted);
        Assert.Equal("SM2-GM", r.Entries[0].EncryptionAlgorithm);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());

        var test = GeneralZip.Test(zip, o => o.Password = kp.PrivateKeyHex);
        Assert.True(test.Success);
    }

    [Fact]
    public void Sm2Gm_WrongPrivateKeyFailsFast()
    {
        if (SkipIfNoCore()) return;
        var zip = Path.Combine(_dir, "sm2-wrong.zip");
        var kp = Sm2KeyPair.Generate();
        var other = Sm2KeyPair.Generate();

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
        {
            o.EncryptionAlgorithm = "SM2-GM";
            o.RecipientPublicKey = kp.PublicKeyHex;
        }))
        {
            w.AddStream("secret.txt", new MemoryStream(new byte[] { 1, 2, 3 }), 3);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip, o => o.Password = other.PrivateKeyHex);
        Assert.Throws<InvalidPasswordException>(() =>
        {
            using var s = r.OpenEntryStream(r.Entries[0]);
            s.CopyTo(Stream.Null);
        });
    }

    [Fact]
    public void Sm2Gm_WriteRequiresRecipientKey()
    {
        var zip = Path.Combine(_dir, "sm2-nokey.zip");
        using var w = GeneralZipWriter.CreateNew(zip, o => o.EncryptionAlgorithm = "SM2-GM");
        Assert.Throws<ArgumentException>(() =>
        {
            w.AddStream("x", new MemoryStream(new byte[] { 1 }), 1);
            w.Finish();
        });
    }

    [Fact]
    public void Kdf_PluggableSha256Roundtrip()
    {
        var zip = Path.Combine(_dir, "kdf256.zip");
        var password = TestSecrets.NewPassword();
        var payload = Encoding.UTF8.GetBytes("PBKDF2-SHA256 KDF payload");

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
        {
            o.EncryptionAlgorithm = "SM4-GM";
            o.KdfAlgorithmId = "PBKDF2-SHA256";
            o.Password = password;
        }))
        {
            w.AddStream("data.bin", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip, o => o.Password = password);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());
    }

    [Fact]
    public void Kdf_Sm3DefaultStillWorks()
    {
        var zip = Path.Combine(_dir, "kdfsm3.zip");
        var password = TestSecrets.NewPassword();
        var payload = new byte[] { 9, 8, 7 };

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
        {
            o.EncryptionAlgorithm = "SM4-GM";
            o.Password = password; // 不设 KdfAlgorithmId → 默认 SM3-PBKDF2
        }))
        {
            w.AddStream("a.bin", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip, o => o.Password = password);
        using var s = r.OpenEntryStream(r.Entries[0]);
        var buf = new byte[3];
        Assert.Equal(3, ReadFull(s, buf));
    }

    [Fact]
    public void Kdf_RegistryBuiltins()
    {
        Assert.Equal((byte)1, GeneralZip.Encryption.Kdfs.FindByName("SM3-PBKDF2")?.SpecId);
        Assert.Equal((byte)2, GeneralZip.Encryption.Kdfs.FindByName("PBKDF2-SHA256")?.SpecId);
        Assert.NotNull(GeneralZip.Encryption.Kdfs.Find(1));
        Assert.NotNull(GeneralZip.Encryption.Kdfs.Find(2));
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void Kdf_Pbkdf2Sha256MatchesBcl()
    {
        // 与 .NET 内置 Rfc2898DeriveBytes（SHA256）一致性（RFC 8018 循环正确性）
        for (var i = 0; i < 5; i++)
        {
            var password = TestSecrets.NewPassword();
            var salt = Kdf.RandomBytes(16);
            var iterations = 1000 + i * 137;
            var length = 16 + i * 17;

            using var bcl = new System.Security.Cryptography.Rfc2898DeriveBytes(
                password, salt, iterations, System.Security.Cryptography.HashAlgorithmName.SHA256);
            var expected = bcl.GetBytes(length);
            var actual = Pbkdf2Sha256KdfProvider.Pbkdf2HmacSha256(
                Encoding.UTF8.GetBytes(password), salt, iterations, length);
            Assert.Equal(expected, actual);
        }
    }
#endif

    private static int ReadFull(Stream s, byte[] buf)
    {
        var total = 0;
        int n;
        while (total < buf.Length && (n = s.Read(buf, total, buf.Length - total)) > 0)
        {
            total += n;
        }

        return total;
    }
}
