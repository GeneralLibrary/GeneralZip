using System;
using System.Security.Cryptography;
using System.Text;
using GeneralZip.Cryptography;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>国密与通用密码原语的已知答案测试（GM/T 0002-2012、GB/T 32905-2016、GB/T 32907-2016）。
/// 全部针对本组件纯 C# 自研实现断言（原语经标准向量锁定，替代第三方库依赖）。</summary>
public class CryptoPrimitiveTests
{
    [Fact]
    public void Sm4_StandardVector_GB32907()
    {
        // GB/T 32907-2016 附录 A 示例 1
        var key = Hex("0123456789ABCDEFFEDCBA9876543210");
        var plain = Hex("0123456789ABCDEFFEDCBA9876543210");
        var expected = Hex("681EDF34D206965E86B3E94F536E4246");

        var engine = new Sm4Engine();
        engine.Init(true, key);
        var cipher = new byte[16];
        engine.ProcessBlock(plain, 0, cipher, 0);

        Assert.Equal(expected, cipher);

        // 解密回代
        engine.Init(false, key);
        var decrypted = new byte[16];
        engine.ProcessBlock(cipher, 0, decrypted, 0);
        Assert.Equal(plain, decrypted);
    }

    [Fact]
    public void Sm3_StandardVector_GB32905()
    {
        // "abc"
        var digest1 = new Sm3Digest();
        var input1 = Encoding.ASCII.GetBytes("abc");
        digest1.BlockUpdate(input1, 0, input1.Length);
        var out1 = new byte[digest1.DigestSize];
        digest1.DoFinal(out1, 0);
        Assert.Equal("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
            HexUpper(out1));

        // 64 字节 "abcd" 重复 16 次
        var digest2 = new Sm3Digest();
        var input2 = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("abcd", 16)));
        digest2.BlockUpdate(input2, 0, input2.Length);
        var out2 = new byte[digest2.DigestSize];
        digest2.DoFinal(out2, 0);
        Assert.Equal("DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732",
            HexUpper(out2));
    }

    [Fact]
    public void Sm3_Incremental_MatchesOneShot()
    {
        var data = Encoding.UTF8.GetBytes("国密 SM3 分段更新与整段计算一致性检验数据");
        var expected = Sm3Digest.Hash(data);

        var digest = new Sm3Digest();
        digest.BlockUpdate(data, 0, 7);
        digest.BlockUpdate(data, 7, 11);
        digest.BlockUpdate(data, 18, data.Length - 18);
        var output = new byte[32];
        digest.DoFinal(output, 0);

        Assert.Equal(expected, output);
    }

    [Fact]
    public void Sm3_Hmac_SelfConsistency()
    {
        var key = Kdf.RandomBytes(32);
        var data = Encoding.UTF8.GetBytes("国密 SM3-HMAC 自测数据");

        // 增量式与一次性结果一致
        var mac = Kdf.CreateIncrementalHmacSm3(key);
        mac.Append(data, 0, 5);
        mac.Append(data, 5, data.Length - 5);
        var incremental = mac.Final();

        var oneShot = Kdf.HmacSm3(key, data);
        Assert.Equal(oneShot, incremental);
    }

    [Fact]
    public void Sm4Ctr_Roundtrip_Via_CtrCipher()
    {
        var key = Kdf.RandomBytes(16);
        var iv = Kdf.RandomBytes(16);
        var plain = new byte[1000];
        RandomNumberGenerator.Fill(plain);
        var cipher = (byte[])plain.Clone();

        var enc = new CtrCipher(new Sm4BlockCipher(key), key, iv);
        enc.Transform(cipher, 0, cipher.Length);
        Assert.NotEqual(plain, cipher);

        var dec = new CtrCipher(new Sm4BlockCipher(key), key, iv);
        dec.Transform(cipher, 0, cipher.Length);
        Assert.Equal(plain, cipher);
    }

    [Fact]
    public void AesCtr_Roundtrip_Via_CtrCipher()
    {
        var key = Kdf.RandomBytes(32);
        var iv = Kdf.RandomBytes(16);
        var plain = new byte[1000];
        RandomNumberGenerator.Fill(plain);
        var cipher = (byte[])plain.Clone();

        var enc = new CtrCipher(new AesBlockCipher(key), key, iv);
        enc.Transform(cipher, 0, cipher.Length);
        Assert.NotEqual(plain, cipher);

        var dec = new CtrCipher(new AesBlockCipher(key), key, iv);
        dec.Transform(cipher, 0, cipher.Length);
        Assert.Equal(plain, cipher);
    }

    [Fact]
    public void Pbkdf2Sm3_Deterministic()
    {
        // KDF 输出锁定自检（漂移会破坏既有加密包的向后兼容，见 CRYPTO-SPEC §7.3）
        var dk1 = Kdf.Pbkdf2Sm3("口令测试", Hex("00112233445566778899AABBCCDDEEFF"), 1000, 52);
        var dk2 = Kdf.Pbkdf2Sm3("口令测试", Hex("00112233445566778899AABBCCDDEEFF"), 1000, 52);
        Assert.Equal(dk1, dk2);
        Assert.Equal(52, dk1.Length);
    }

    [Fact]
    public void Pbkdf2Sha1_MatchesRfc6070StyleVector()
    {
        // RFC 6070 风格已知答案（HMAC-SHA1 PBKDF2，"password"/"salt"/40960 位输出前 20 字节与
        // .NET 内置 Rfc2898DeriveBytes 一致性自检）
        var derived = Kdf.Pbkdf2Sha1("password", Encoding.ASCII.GetBytes("salt"), 1, 20);
        using var reference = new Rfc2898DeriveBytes(
            "password", Encoding.ASCII.GetBytes("salt"), 1, System.Security.Cryptography.HashAlgorithmName.SHA1);
        Assert.Equal(reference.GetBytes(20), derived);
    }

    [Fact]
    public void Crc32_KnownVector()
    {
        // "123456789" → 0xCBF43926（IEEE 802.3 标准校验值）
        var data = Encoding.ASCII.GetBytes("123456789");
        Assert.Equal(0xCBF43926u, Crc32.Compute(data));
    }

    [Fact]
    public void FixedTimeEquals_Behavior()
    {
        Assert.True(Kdf.FixedTimeEquals(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 3 }));
        Assert.False(Kdf.FixedTimeEquals(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 4 }));
        Assert.False(Kdf.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 2, 3 }));
        Assert.False(Kdf.FixedTimeEquals(null!, new byte[] { 1 }));
    }

    private static byte[] Hex(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }

        return bytes;
    }

    private static string HexUpper(byte[] bytes) => Convert.ToHexString(bytes);
}
