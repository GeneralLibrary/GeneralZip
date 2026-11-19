using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using GeneralZip.Abstractions;

namespace GeneralZip.Cryptography;

/// <summary>
/// 国密 SM2 信封混合加密（GeneralZip 自定义 ZIP 扩展，规范见 docs/CRYPTO-SPEC.md §7）。
/// <para>extra field 0x4D54："GMSN" 容器：每条目随机数据密钥（SM4-CTR + SM3-HMAC，EtM），
/// 数据密钥整体经 SM2 公钥加密（ECIES，C1‖C3‖C2）装入信封。写侧只需接收方公钥（无需口令），
/// 读侧以 SM2 私钥（hex）作为"口令"经既有口令协商管线提供。</para>
/// </summary>
public sealed class Sm2GmProvider : IEncryptionProvider, IPasswordlessWriteProvider
{
    public const ushort ExtraFieldId = 0x4D54;

    private const byte SpecVersion = 1;
    private const byte CipherModeCtr = 1;
    private const byte KdfIdEnvelope = 0; // 信封模式：数据密钥不由口令派生

    private const int KeyLength = 16;    // SM4 数据密钥
    private const int MacKeyLength = 32; // SM3-HMAC 密钥
    private const int IvLength = 16;     // SM4-CTR IV
    private const int MacLength = 32;    // SM3 输出
    private const int EnvelopePlainLength = KeyLength + MacKeyLength + IvLength;
    private const int EnvelopeLength = 65 + 32 + EnvelopePlainLength; // C1‖C3‖C2

    public string AlgorithmId => "SM2-GM";

    public bool SupportsWrite => true;

    public bool SupportsRead => true;

    public IReadOnlyCollection<ushort> ZipExtraFieldIds { get; } = new ushort[] { ExtraFieldId };

    public EntryEncryptionPlan PrepareWrite(EncryptionWriteContext context)
    {
        if (context.RecipientPublicKey == null || context.RecipientPublicKey.Length == 0)
        {
            throw new ArgumentException(
                "Algorithm SM2-GM requires the recipient's SM2 public key (options.RecipientPublicKey)",
                nameof(context));
        }

        var publicKey = Sm2.DecodePoint(context.RecipientPublicKey);

        // 随机数据密钥：K_enc ‖ K_mac ‖ IV
        var keyEnc = Kdf.RandomBytes(KeyLength);
        var keyMac = Kdf.RandomBytes(MacKeyLength);
        var iv = Kdf.RandomBytes(IvLength);
        var keyBlob = new byte[EnvelopePlainLength];
        Buffer.BlockCopy(keyEnc, 0, keyBlob, 0, KeyLength);
        Buffer.BlockCopy(keyMac, 0, keyBlob, KeyLength, MacKeyLength);
        Buffer.BlockCopy(iv, 0, keyBlob, KeyLength + MacKeyLength, IvLength);

        byte[] envelope;
        try
        {
            envelope = Sm2.Encrypt(keyBlob, publicKey);
        }
        finally
        {
            Kdf.Zero(keyBlob);
        }

        // extra field 数据区（HMAC 的 AAD），布局见 CRYPTO-SPEC.md §7
        var aad = BuildExtraFieldData(envelope, context.RealCompressionMethod);

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
            throw new ArchiveCorruptedException("SM2-GM extra field is missing", context.EntryName);
        }

        var parsed = ParseExtraField(extra, context.EntryName);
        if (context.CipherDataSize >= 0 && context.CipherDataSize < MacLength)
        {
            throw new ArchiveCorruptedException("SM2-GM ciphertext data is too short", context.EntryName);
        }

        // "口令" = SM2 私钥 hex
        if (string.IsNullOrEmpty(context.Password))
        {
            throw new InvalidPasswordException(context.EntryName);
        }

        BigInteger privateKey;
        try
        {
            privateKey = ParsePrivateKey(context.Password!);
        }
        catch (ArgumentException)
        {
            // 口令不是合法私钥 hex → 口令错误
            throw new InvalidPasswordException(context.EntryName);
        }

        // 解封数据密钥：SM2 ECIES 的 C3 校验在解密内完成，错误私钥/篡改在此快速失败
        byte[] keyBlob;
        try
        {
            keyBlob = Sm2.Decrypt(parsed.Envelope, privateKey);
        }
        catch (InvalidOperationException)
        {
            throw new InvalidPasswordException(context.EntryName);
        }
        catch (ArgumentException ex)
        {
            throw new ArchiveCorruptedException($"Invalid SM2-GM envelope: {ex.Message}", context.EntryName);
        }

        var keyEnc = new byte[KeyLength];
        var keyMac = new byte[MacKeyLength];
        var iv = new byte[IvLength];
        Buffer.BlockCopy(keyBlob, 0, keyEnc, 0, KeyLength);
        Buffer.BlockCopy(keyBlob, KeyLength, keyMac, 0, MacKeyLength);
        Buffer.BlockCopy(keyBlob, KeyLength + MacKeyLength, iv, 0, IvLength);
        Kdf.Zero(keyBlob);

        var payloadLength = context.CipherDataSize - MacLength;
        var cipher = new CtrCipher(new Sm4BlockCipher(keyEnc), keyEnc, iv);
        var mac = Kdf.CreateIncrementalHmacSm3(keyMac);
        return new CtrReadStream(cipherSource, cipher, mac, payloadLength, new[] { extra });
    }

    // ---------- 构建与解析 ----------

    private static byte[] BuildExtraFieldData(byte[] envelope, ushort realMethod)
    {
        // Magic(4) Ver(1) Mode(1) Kdf(1) EnvLen(4) Envelope(EnvLen) RealMethod(2)
        var data = new byte[4 + 1 + 1 + 1 + 4 + envelope.Length + 2];
        var pos = 0;

        data[pos++] = (byte)'G';
        data[pos++] = (byte)'M';
        data[pos++] = (byte)'S';
        data[pos++] = (byte)'N';
        data[pos++] = SpecVersion;
        data[pos++] = CipherModeCtr;
        data[pos++] = KdfIdEnvelope;
        data[pos++] = (byte)(envelope.Length & 0xFF);
        data[pos++] = (byte)((envelope.Length >> 8) & 0xFF);
        data[pos++] = (byte)((envelope.Length >> 16) & 0xFF);
        data[pos++] = (byte)((envelope.Length >> 24) & 0xFF);
        Buffer.BlockCopy(envelope, 0, data, pos, envelope.Length);
        pos += envelope.Length;
        data[pos++] = (byte)(realMethod & 0xFF);
        data[pos++] = (byte)((realMethod >> 8) & 0xFF);
        return data;
    }

    private readonly struct ParsedExtra
    {
        public ParsedExtra(byte[] envelope, ushort realMethod)
        {
            Envelope = envelope;
            RealMethod = realMethod;
        }

        public byte[] Envelope { get; }
        public ushort RealMethod { get; }
    }

    private static ParsedExtra ParseExtraField(byte[] data, string entryName)
    {
        const int minLength = 4 + 1 + 1 + 1 + 4 + 2;
        if (data.Length < minLength
            || data[0] != (byte)'G' || data[1] != (byte)'M' || data[2] != (byte)'S' || data[3] != (byte)'N')
        {
            throw new ArchiveCorruptedException("Invalid SM2-GM extra field (magic/length)", entryName);
        }

        var version = data[4];
        if (version != SpecVersion)
        {
            throw new UnsupportedFormatException($"Unsupported SM2-GM spec version {version} (supported: {SpecVersion})", entryName);
        }

        var mode = data[5];
        if (mode != CipherModeCtr)
        {
            throw new UnsupportedFormatException($"Unsupported SM2-GM cipher mode {mode}", entryName);
        }

        var pos = 7;
        var envelopeLength = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24);
        pos += 4;

        if (envelopeLength != EnvelopeLength || pos + envelopeLength + 2 > data.Length)
        {
            throw new ArchiveCorruptedException($"Invalid SM2-GM envelope length {envelopeLength}", entryName);
        }

        var envelope = new byte[envelopeLength];
        Buffer.BlockCopy(data, pos, envelope, 0, envelopeLength);
        pos += envelopeLength;

        var realMethod = (ushort)(data[pos] | (data[pos + 1] << 8));
        return new ParsedExtra(envelope, realMethod);
    }

    private static BigInteger ParsePrivateKey(string hex)
    {
        var clean = hex.Trim();
        var d = Sm2.FromHex(clean);
        if (d <= 0 || d >= Sm2.Order - 1)
        {
            throw new ArgumentException("private key out of range");
        }

        return d;
    }
}
