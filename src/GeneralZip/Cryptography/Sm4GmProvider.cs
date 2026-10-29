using System;
using System.Collections.Generic;
using System.IO;
using GeneralZip.Abstractions;

namespace GeneralZip.Cryptography;

/// <summary>
/// 国密 SM4-GM 加密（GeneralZip 自定义 ZIP 扩展，规范见 docs/CRYPTO-SPEC.md）。
/// <para>extra field 0x4D53："GMSM" 容器：SM3-PBKDF2 派生（域分离三子密钥）+ SM4-CTR + SM3-HMAC（Encrypt-then-MAC）。</para>
/// <para>口令校验值 4 字节支持错误口令快速失败；HMAC 覆盖 extra field 参数与全部密文。</para>
/// </summary>
public sealed class Sm4GmProvider : IEncryptionProvider
{
    public const ushort ExtraFieldId = 0x4D53;

    private const byte SpecVersion = 1;
    private const byte CipherModeCtr = 1;
    private const byte KdfIdPbkdf2Sm3 = 1;

    private const int KeyLength = 16;      // SM4 密钥
    private const int MacKeyLength = 32;   // SM3-HMAC 密钥
    private const int VerifierLength = 4;  // 口令校验值
    private const int SaltLength = 16;
    private const int IvLength = 16;
    private const int MacLength = 32;      // SM3 输出

    /// <summary>KDF 默认迭代次数（可由 options.KdfIterations 覆盖）。</summary>
    public const int DefaultIterations = 10_000;

    public string AlgorithmId => "SM4-GM";

    public bool SupportsWrite => true;

    public bool SupportsRead => true;

    public IReadOnlyCollection<ushort> ZipExtraFieldIds { get; } = new ushort[] { ExtraFieldId };

    public EntryEncryptionPlan PrepareWrite(EncryptionWriteContext context)
    {
        var iterations = context.KdfIterations > 0 ? context.KdfIterations : DefaultIterations;
        var salt = Kdf.RandomBytes(SaltLength);
        var iv = Kdf.RandomBytes(IvLength);

        // 先派生密钥：校验值（K_ver）必须进入 extra field，而 extra field 又是 HMAC 的 AAD
        var keyMaterial = Kdf.Pbkdf2Sm3(context.Password, salt, iterations, KeyLength + MacKeyLength + VerifierLength);
        var keyEnc = new byte[KeyLength];
        var keyMac = new byte[MacKeyLength];
        var verifier = new byte[VerifierLength];
        Buffer.BlockCopy(keyMaterial, 0, keyEnc, 0, KeyLength);
        Buffer.BlockCopy(keyMaterial, KeyLength, keyMac, 0, MacKeyLength);
        Buffer.BlockCopy(keyMaterial, KeyLength + MacKeyLength, verifier, 0, VerifierLength);
        Kdf.Zero(keyMaterial);

        // extra field 数据区（HMAC 的 AAD），布局见 CRYPTO-SPEC.md §5
        var aad = BuildExtraFieldData(iterations, salt, iv, verifier, context.RealCompressionMethod);

        return new EntryEncryptionPlan(
            ExtraFieldId,
            aad,
            MacLength,
            sink =>
            {
                var cipher = new CtrCipher(new Sm4BlockCipher(keyEnc), keyEnc, iv);
                var mac = Kdf.CreateIncrementalHmacSm3(keyMac);
                return new CtrWriteStream(sink, cipher, mac, MacLength, new[] { aad });
            });
    }

    public Stream OpenRead(Stream cipherSource, EncryptionReadContext context)
    {
        if (!context.Parameters.TryGetValue("ZipExtraFieldData", out var raw) || raw is not byte[] extra)
        {
            throw new ArchiveCorruptedException("缺少 SM4-GM extra field", context.EntryName);
        }

        var parsed = ParseExtraField(extra, context.EntryName);
        if (context.CipherDataSize >= 0 && context.CipherDataSize < MacLength)
        {
            throw new ArchiveCorruptedException("SM4-GM 密文数据长度不足", context.EntryName);
        }

        var payloadLength = context.CipherDataSize - MacLength;

        // 口令快速失败：先派生 K_ver 与存储校验值比较
        var keyMaterial = Kdf.Pbkdf2Sm3(context.Password, parsed.Salt, parsed.Iterations, KeyLength + MacKeyLength + VerifierLength);
        var keyEnc = new byte[KeyLength];
        var keyMac = new byte[MacKeyLength];
        var verifier = new byte[VerifierLength];
        Buffer.BlockCopy(keyMaterial, 0, keyEnc, 0, KeyLength);
        Buffer.BlockCopy(keyMaterial, KeyLength, keyMac, 0, MacKeyLength);
        Buffer.BlockCopy(keyMaterial, KeyLength + MacKeyLength, verifier, 0, VerifierLength);
        Kdf.Zero(keyMaterial);

        if (!Kdf.FixedTimeEquals(verifier, parsed.Verifier))
        {
            throw new InvalidPasswordException(context.EntryName);
        }

        var cipher = new CtrCipher(new Sm4BlockCipher(keyEnc), keyEnc, parsed.Iv);
        var mac = Kdf.CreateIncrementalHmacSm3(keyMac);
        return new CtrReadStream(cipherSource, cipher, mac, payloadLength, new[] { extra });
    }

    // ---------- 构建与解析 ----------

    /// <summary>
    /// 构建 extra field 数据区。
    /// </summary>
    private static byte[] BuildExtraFieldData(int iterations, byte[] salt, byte[] iv, byte[] verifier, ushort realMethod)
    {
        // Magic(4) Ver(1) Mode(1) Kdf(1) Iter(4) SaltLen(1) Salt IvLen(1) IV VerifierLen(1)→4 直接内嵌 Verifier(4) RealMethod(2)
        var data = new byte[4 + 1 + 1 + 1 + 4 + 1 + SaltLength + 1 + IvLength + 4 + 2];
        var pos = 0;

        data[pos++] = (byte)'G';
        data[pos++] = (byte)'M';
        data[pos++] = (byte)'S';
        data[pos++] = (byte)'M';
        data[pos++] = SpecVersion;
        data[pos++] = CipherModeCtr;
        data[pos++] = KdfIdPbkdf2Sm3;
        PutLe32(data, ref pos, iterations);
        data[pos++] = SaltLength;
        Buffer.BlockCopy(salt, 0, data, pos, SaltLength);
        pos += SaltLength;
        data[pos++] = IvLength;
        Buffer.BlockCopy(iv, 0, data, pos, IvLength);
        pos += IvLength;
        if (verifier != null)
        {
            Buffer.BlockCopy(verifier, 0, data, pos, VerifierLength);
        }

        pos += VerifierLength;
        data[pos++] = (byte)(realMethod & 0xFF);
        data[pos++] = (byte)((realMethod >> 8) & 0xFF);
        return data;
    }

    private static ParsedExtra ParseExtraField(byte[] data, string entryName)
    {
        const int minLength = 4 + 1 + 1 + 1 + 4 + 1 + SaltLength + 1 + IvLength + VerifierLength + 2;
        if (data.Length < minLength
            || data[0] != (byte)'G' || data[1] != (byte)'M' || data[2] != (byte)'S' || data[3] != (byte)'M')
        {
            throw new ArchiveCorruptedException("SM4-GM extra field 非法（Magic/长度）", entryName);
        }

        var version = data[4];
        if (version != SpecVersion)
        {
            throw new UnsupportedFormatException($"SM4-GM 规范版本 {version} 不受支持（当前 {SpecVersion}）", entryName);
        }

        var mode = data[5];
        if (mode != CipherModeCtr)
        {
            throw new UnsupportedFormatException($"SM4-GM 加密模式 {mode} 不受支持", entryName);
        }

        var kdfId = data[6];
        if (kdfId != KdfIdPbkdf2Sm3)
        {
            throw new UnsupportedFormatException($"SM4-GM KDF 标识 {kdfId} 不受支持", entryName);
        }

        var pos = 7;
        var iterations = GetLe32(data, ref pos);
        var saltLen = data[pos++];
        if (saltLen != SaltLength)
        {
            throw new UnsupportedFormatException($"SM4-GM 盐长度 {saltLen} 不受支持", entryName);
        }

        var salt = new byte[saltLen];
        Buffer.BlockCopy(data, pos, salt, 0, saltLen);
        pos += saltLen;

        var ivLen = data[pos++];
        if (ivLen != IvLength)
        {
            throw new UnsupportedFormatException($"SM4-GM IV 长度 {ivLen} 不受支持", entryName);
        }

        var iv = new byte[ivLen];
        Buffer.BlockCopy(data, pos, iv, 0, ivLen);
        pos += ivLen;

        var verifier = new byte[VerifierLength];
        Buffer.BlockCopy(data, pos, verifier, 0, VerifierLength);
        pos += VerifierLength;

        var realMethod = (ushort)(data[pos] | (data[pos + 1] << 8));
        return new ParsedExtra(iterations, salt, iv, verifier, realMethod);
    }

    private static void PutLe32(byte[] buffer, ref int pos, int value)
    {
        buffer[pos++] = (byte)value;
        buffer[pos++] = (byte)(value >> 8);
        buffer[pos++] = (byte)(value >> 16);
        buffer[pos++] = (byte)(value >> 24);
    }

    private static int GetLe32(byte[] buffer, ref int pos)
    {
        var v = buffer[pos] | (buffer[pos + 1] << 8) | (buffer[pos + 2] << 16) | (buffer[pos + 3] << 24);
        pos += 4;
        return v;
    }

    private readonly struct ParsedExtra
    {
        public ParsedExtra(int iterations, byte[] salt, byte[] iv, byte[] verifier, ushort realMethod)
        {
            Iterations = iterations;
            Salt = salt;
            Iv = iv;
            Verifier = verifier;
            RealMethod = realMethod;
        }

        public int Iterations { get; }
        public byte[] Salt { get; }
        public byte[] Iv { get; }
        public byte[] Verifier { get; }
        public ushort RealMethod { get; }
    }
}
