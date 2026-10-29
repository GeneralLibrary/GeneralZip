using System;
using System.Collections.Generic;
using System.IO;
using GeneralZip.Abstractions;

namespace GeneralZip.Cryptography;

/// <summary>AES key strength.</summary>
public enum AesKeyStrength
{
    Bits128 = 1,
    Bits192 = 2,
    Bits256 = 3,
}

/// <summary>
/// WinZip AES encryption (APPNOTE extra field 0x9901, AE-2 semantics).
/// Entry data layout: [salt][2B password verifier][AES-CTR ciphertext][10B truncated HMAC-SHA1].
/// Interoperable with WinZip / 7-Zip / Windows Explorer and other mainstream tools.
/// </summary>
public sealed class WinZipAesProvider : IEncryptionProvider
{
    public const ushort ExtraFieldId = 0x9901;
    private const int Iterations = 1000;
    private const int AuthCodeLength = 10;

    private readonly AesKeyStrength _strength;

    public WinZipAesProvider(AesKeyStrength strength)
    {
        if (strength == AesKeyStrength.Bits192)
        {
            throw new NotSupportedException("WinZip AES-192 is rare and offers no benefit; this component supports 128/256 only");
        }

        _strength = strength;
    }

    public string AlgorithmId => _strength == AesKeyStrength.Bits128 ? "WinZipAES128" : "WinZipAES256";

    public bool SupportsWrite => true;

    public bool SupportsRead => true;

    public IReadOnlyCollection<ushort> ZipExtraFieldIds { get; } = new ushort[] { ExtraFieldId };

    private int KeyBytes => _strength == AesKeyStrength.Bits128 ? 16 : 32;

    private int SaltBytes => _strength == AesKeyStrength.Bits128 ? 8 : 16;

    private byte StrengthCode => _strength == AesKeyStrength.Bits128 ? (byte)1 : (byte)3;

    public EntryEncryptionPlan PrepareWrite(EncryptionWriteContext context)
    {
        var salt = Kdf.RandomBytes(SaltBytes);
        var keyMaterial = Kdf.Pbkdf2Sha1(context.Password, salt, Iterations, (KeyBytes * 2) + 2);

        var keyEnc = new byte[KeyBytes];
        var keyMac = new byte[KeyBytes];
        var verify = new byte[2];
        Buffer.BlockCopy(keyMaterial, 0, keyEnc, 0, KeyBytes);
        Buffer.BlockCopy(keyMaterial, KeyBytes, keyMac, 0, KeyBytes);
        Buffer.BlockCopy(keyMaterial, KeyBytes * 2, verify, 0, 2);
        Kdf.Zero(keyMaterial);

        // extra field data: version (AE-2) | vendor "AE" | strength | real compression method
        var extra = new byte[7];
        extra[0] = 0x02;
        extra[1] = 0x00;
        extra[2] = (byte)'A';
        extra[3] = (byte)'E';
        extra[4] = StrengthCode;
        extra[5] = (byte)(context.RealCompressionMethod & 0xFF);
        extra[6] = (byte)((context.RealCompressionMethod >> 8) & 0xFF);

        var overhead = SaltBytes + 2 + AuthCodeLength;
        // WinZip convention: 128-bit little-endian counter starting at 1
        var zeroIv = new byte[16];

        return new EntryEncryptionPlan(
            ExtraFieldId,
            extra,
            overhead,
            sink =>
            {
                sink.Write(salt, 0, salt.Length);
                sink.Write(verify, 0, verify.Length);
                var cipher = new CtrCipher(new AesBlockCipher(keyEnc), keyEnc, zeroIv, littleEndian: true);
                var mac = Kdf.CreateIncrementalHmacSha1(keyMac);
                return new CtrWriteStream(sink, cipher, mac, AuthCodeLength);
            });
    }

    public Stream OpenRead(Stream cipherSource, EncryptionReadContext context)
    {
        if (!context.Parameters.TryGetValue("ZipExtraFieldData", out var raw) || raw is not byte[] extra || extra.Length < 7)
        {
            throw new ArchiveCorruptedException("WinZip AES extra field is missing", context.EntryName);
        }

        var strengthCode = extra[4];
        if ((strengthCode == 1 && KeyBytes != 16) || (strengthCode == 3 && KeyBytes != 32))
        {
            throw new UnsupportedFormatException(
                $"Entry is WinZip AES-{(strengthCode == 1 ? 128 : 256)} which does not match provider {AlgorithmId}", context.EntryName);
        }

        if (context.CipherDataSize >= 0 && context.CipherDataSize < SaltBytes + 2 + AuthCodeLength)
        {
            throw new ArchiveCorruptedException("WinZip AES ciphertext data is too short", context.EntryName);
        }

        var payloadLength = context.CipherDataSize - SaltBytes - 2 - AuthCodeLength;
        return WinZipAesReadStream.Create(cipherSource, context.Password, payloadLength, context.EntryName, KeyBytes, SaltBytes, AuthCodeLength);
    }

    /// <summary>Read-side stream consuming [salt][verify2][ciphertext][auth10].</summary>
    private sealed class WinZipAesReadStream : CtrReadStream
    {
        private WinZipAesReadStream(Stream source, CtrCipher cipher, HmacSha1Incremental mac, long payloadLength, int trailerLength)
            : base(source, cipher, mac, payloadLength, trailerLength: trailerLength)
        {
        }

        public static WinZipAesReadStream Create(
            Stream source, string password, long payloadLength, string entryName, int keyBytes, int saltBytes, int trailerLength)
        {
            // 1) read salt + password verifier
            var salt = new byte[saltBytes];
            ReadExactly(source, salt);
            var verifyStored = new byte[2];
            ReadExactly(source, verifyStored);

            // 2) derive keys and verify the password (fast fail)
            var keyMaterial = Kdf.Pbkdf2Sha1(password, salt, Iterations, (keyBytes * 2) + 2);
            var keyEnc = new byte[keyBytes];
            var keyMac = new byte[keyBytes];
            var verify = new byte[2];
            Buffer.BlockCopy(keyMaterial, 0, keyEnc, 0, keyBytes);
            Buffer.BlockCopy(keyMaterial, keyBytes, keyMac, 0, keyBytes);
            Buffer.BlockCopy(keyMaterial, keyBytes * 2, verify, 0, 2);
            Kdf.Zero(keyMaterial);

            if (!Kdf.FixedTimeEquals(verify, verifyStored))
            {
                throw new InvalidPasswordException(entryName);
            }

            // 3) CTR (WinZip little-endian counter starting at 1) + HMAC-SHA1
            var counterStart = new byte[16];
            counterStart[0] = 1;
            var cipher = new CtrCipher(new AesBlockCipher(keyEnc), keyEnc, counterStart, littleEndian: true);
            var mac = Kdf.CreateIncrementalHmacSha1(keyMac);
            return new WinZipAesReadStream(source, cipher, mac, payloadLength, trailerLength);
        }

        private static void ReadExactly(Stream source, byte[] buffer)
        {
            var total = 0;
            while (total < buffer.Length)
            {
                var n = source.Read(buffer, total, buffer.Length - total);
                if (n <= 0)
                {
                    throw new ArchiveCorruptedException("WinZip AES header (salt/verifier) is incomplete");
                }

                total += n;
            }
        }
    }
}
