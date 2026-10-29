using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using GeneralZip.Abstractions;

namespace GeneralZip.Cryptography;

/// <summary>ZipCrypto 三密钥状态（独立类以避免 MarshalByRefObject 字段 ref 限制）。</summary>
internal sealed class ZipCryptoKeys
{
    // PKWARE 规范初始密钥
    public uint K0 = 0x12345678u;
    public uint K1 = 0x23456789u;
    public uint K2 = 0x34567890u;

    public void Update(byte b)
    {
        K0 = Crc32.Table[(K0 ^ b) & 0xFF] ^ (K0 >> 8);
        K1 = unchecked((K1 + (K0 & 0xFF)) * 134775813u + 1u);
        K2 = Crc32.Table[(K2 ^ (byte)(K1 >> 24)) & 0xFF] ^ (K2 >> 8);
    }

    public byte DecryptByte()
    {
        var temp = (K2 & 0xFFFF) | 2;
        return (byte)((temp * (temp ^ 1)) >> 8);
    }
}

/// <summary>
/// PKWARE 传统 ZipCrypto 加密（ZIP 2.0 弱加密）。
/// 仅为兼容遗留归档保留：读取默认支持；写入需显式启用（安全审计场景禁用）。
/// 数据布局：[12 字节加密头（末字节为校验字节）][异或流密文]。
/// </summary>
public sealed class ZipCryptoProvider : IEncryptionProvider
{
    public string AlgorithmId => "ZipCrypto";

    public bool SupportsWrite => true;

    public bool SupportsRead => true;

    public IReadOnlyCollection<ushort> ZipExtraFieldIds { get; } = Array.Empty<ushort>();

    public EntryEncryptionPlan PrepareWrite(EncryptionWriteContext context)
    {
        // 规范：数据描述符（bit 3）模式校验字节取 DOS 时间高字节；否则取 CRC 高字节
        byte checkByte;
        if (context.DosTime != 0)
        {
            checkByte = (byte)((context.DosTime >> 8) & 0xFF);
        }
        else if (context.Crc32.HasValue)
        {
            checkByte = (byte)((context.Crc32.Value >> 24) & 0xFF);
        }
        else
        {
            throw new ArgumentException("ZipCrypto 需要 Crc32 或 DosTime 之一以计算头校验字节", nameof(context));
        }

        return new EntryEncryptionPlan(
            null,
            null,
            12,
            sink => new ZipCryptoWriteStream(sink, context.Password, checkByte));
    }

    public Stream OpenRead(Stream cipherSource, EncryptionReadContext context)
    {
        // 校验字节存在两派写入器：已知 CRC 用 crc>>24（SharpZipLib 等），真流式用 dosTime>>8（Info-ZIP 约定）。
        // 依次尝试；都不中才判定口令错误。
        var candidates = new List<byte>();
        if (context.Parameters.TryGetValue("ZipCryptoCheckByte", out var cb) && cb is byte b)
        {
            candidates.Add(b);
        }

        if (context.Parameters.TryGetValue("ZipCryptoCheckByteAlt", out var cbAlt) && cbAlt is byte alt)
        {
            candidates.Add(alt);
        }

        if (candidates.Count == 0)
        {
            throw new ArchiveCorruptedException("缺少 ZipCrypto 校验字节所需参数", context.EntryName);
        }

        var overhead = context.Parameters.TryGetValue("ZipCryptoHeaderSize", out var hs) && hs is int h ? h : 12;
        var payload = context.CipherDataSize >= 0 ? context.CipherDataSize - overhead : -1;
        return ZipCryptoReadStream.Create(cipherSource, context.Password, candidates, payload, context.EntryName);
    }
}

/// <summary>写侧 ZipCrypto 流：输出 12 字节随机头 + 逐字节异或流加密。</summary>
public sealed class ZipCryptoWriteStream : Stream
{
    private readonly Stream _sink;
    private readonly ZipCryptoKeys _keys = new();
    private bool _headerWritten;
    private readonly byte _checkByte;

    public ZipCryptoWriteStream(Stream sink, string password, byte checkByte)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _checkByte = checkByte;
        var passwordBytes = Encoding.UTF8.GetBytes(password ?? throw new ArgumentNullException(nameof(password)));
        foreach (var b in passwordBytes)
        {
            _keys.Update(b);
        }
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    private void WriteHeader()
    {
        if (_headerWritten) return;
        _headerWritten = true;

        var header = Kdf.RandomBytes(12);
        header[11] = _checkByte;
        for (var i = 0; i < header.Length; i++)
        {
            var plain = header[i];
            header[i] = (byte)(plain ^ _keys.DecryptByte());
            _keys.Update(plain);
        }

        _sink.Write(header, 0, header.Length);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (count <= 0) return;
        WriteHeader();

        var cipher = new byte[count];
        for (var i = 0; i < count; i++)
        {
            var plain = buffer[offset + i];
            cipher[i] = (byte)(plain ^ _keys.DecryptByte());
            _keys.Update(plain);
        }

        _sink.Write(cipher, 0, cipher.Length);
    }

    public override void Flush() => _sink.Flush();

    protected override void Dispose(bool disposing)
    {
        // 零字节条目也要落 12 字节加密头
        if (disposing)
        {
            WriteHeader();
        }

        base.Dispose(disposing);
    }
}

/// <summary>读侧 ZipCrypto 流：消费 12 字节头并校验，然后逐字节解密。</summary>
public sealed class ZipCryptoReadStream : Stream
{
    private readonly Stream _source;
    private readonly ZipCryptoKeys _keys = new();
    private readonly long _payloadLength;
    private readonly string _entryName;
    private long _readBytes;

    private ZipCryptoReadStream(Stream source, long payloadLength, string entryName)
    {
        _source = source;
        _payloadLength = payloadLength;
        _entryName = entryName;
    }

    public static ZipCryptoReadStream Create(Stream source, string password, IReadOnlyList<byte> checkByteCandidates, long payloadLength, string entryName)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password ?? throw new ArgumentNullException(nameof(password)));

        // 加密头只读一次；多个校验字节候选共用同一份原始字节
        var header = new byte[12];
        var total = 0;
        while (total < header.Length)
        {
            var n = source.Read(header, total, header.Length - total);
            if (n <= 0)
            {
                throw new ArchiveCorruptedException("ZipCrypto 加密头不完整", entryName);
            }

            total += n;
        }

        foreach (var checkByte in checkByteCandidates)
        {
            var keys = new ZipCryptoKeys();
            foreach (var b in passwordBytes)
            {
                keys.Update(b);
            }

            var plain = new byte[12];
            for (var i = 0; i < header.Length; i++)
            {
                plain[i] = (byte)(header[i] ^ keys.DecryptByte());
                keys.Update(plain[i]);
            }

            if (plain[11] != checkByte)
            {
                continue; // 尝试下一候选校验字节
            }

            var stream = new ZipCryptoReadStream(source, payloadLength, entryName);
            stream._keys.K0 = keys.K0;
            stream._keys.K1 = keys.K1;
            stream._keys.K2 = keys.K2;
            return stream;
        }

        throw new InvalidPasswordException(entryName);
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _payloadLength;
    public override long Position { get => _readBytes; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_readBytes >= _payloadLength) return 0;

        var toRead = (int)Math.Min(count, _payloadLength - _readBytes);
        var n = _source.Read(buffer, offset, toRead);
        if (n <= 0)
        {
            throw new ArchiveCorruptedException("ZipCrypto 密文数据意外截断", _entryName);
        }

        for (var i = 0; i < n; i++)
        {
            var plain = (byte)(buffer[offset + i] ^ _keys.DecryptByte());
            _keys.Update(plain);
            buffer[offset + i] = plain;
        }

        _readBytes += n;
        return n;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
