using System;
using System.Security.Cryptography;
using GeneralZip;

namespace GeneralZip.Cryptography;

/// <summary>16 字节分组加密原语抽象（屏蔽 .NET AES 与自研 SM4 的差异）。</summary>
public interface IBlockCipher16
{
    /// <summary>加密单个 16 字节分组。</summary>
    void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
}

/// <summary>AES-128/256 分组（.NET 内置）。ECB 模式仅用于加密 CTR 计数器块以生成密钥流
/// （CTR 构造的标准实现，用户数据从不经 ECB 加密）。</summary>
public sealed class AesBlockCipher : IBlockCipher16
{
    private readonly ICryptoTransform _encryptor;

    public AesBlockCipher(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 16 && key.Length != 32) throw new ArgumentException("AES key must be 16 or 32 bytes", nameof(key));

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        _encryptor = aes.CreateEncryptor();
    }

    public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        => _encryptor.TransformBlock(input, inputOffset, 16, output, outputOffset);
}

/// <summary>SM4 分组（本组件纯 C# 实现）。</summary>
public sealed class Sm4BlockCipher : IBlockCipher16
{
    private readonly Sm4Engine _engine = new();

    public Sm4BlockCipher(byte[] key)
    {
        _engine.Init(forEncryption: true, key);
    }

    public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        => _engine.ProcessBlock(input, inputOffset, output, outputOffset);
}

/// <summary>
/// 通用 CTR 模式引擎（任意 16 字节分组密码，如 AES/SM4）。
/// BigEndian：标准 CTR——首块 = E(IV)，计数器按 128 位大端 +1（SM4-GM）。
/// LittleEndian：WinZip AES 约定——计数器自 1 起按小端 +1（首块 = E(1)），IV 参数忽略。
/// </summary>
public sealed class CtrCipher
{
    private readonly IBlockCipher16 _cipher;
    private readonly byte[] _counter;
    private readonly bool _littleEndian;
    private readonly byte[] _keystream = new byte[16];
    private int _keystreamPos;

    public CtrCipher(IBlockCipher16 cipher, byte[] key, byte[] iv, bool littleEndian = false)
    {
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (iv == null || iv.Length != 16) throw new ArgumentException("IV must be 16 bytes", nameof(iv));

        _cipher = cipher;
        _littleEndian = littleEndian;
        _counter = (byte[])iv.Clone();
        if (littleEndian)
        {
            _counter[0] = 1; // WinZip 约定：计数器自 1 起（小端）
            _keystreamPos = 16;
        }
        else
        {
            _keystreamPos = 16; // 强制首块刷新（首块 = E(IV)）
        }
    }

    /// <summary>就地异或加/解密（CTR 对称）。</summary>
    public void Transform(byte[] buffer, int offset, int count)
    {
        for (var i = 0; i < count; i++)
        {
            if (_keystreamPos == 16)
            {
                _cipher.EncryptBlock(_counter, 0, _keystream, 0);
                IncrementCounter(_counter);
                _keystreamPos = 0;
            }

            buffer[offset + i] ^= _keystream[_keystreamPos++];
        }
    }

    private void IncrementCounter(byte[] counter)
    {
        if (_littleEndian)
        {
            for (var i = 0; i < counter.Length; i++)
            {
                if (++counter[i] != 0)
                {
                    break;
                }
            }
        }
        else
        {
            for (var i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                {
                    break;
                }
            }
        }
    }
}

/// <summary>
/// 写侧 CTR 加密流：明文写入 → CTR 加密 → 底层流。
/// 同时增量计算密文的 HMAC，Dispose 时把截断的认证码追加到流尾（Encrypt-then-MAC 收尾）。
/// </summary>
public sealed class CtrWriteStream : Stream
{
    private readonly Stream _sink;
    private readonly CtrCipher _cipher;
    private readonly IncrementalMac _mac;
    private readonly int _trailerLength;
    private readonly byte[] _work = new byte[81920];
    private bool _finished;

    public CtrWriteStream(Stream sink, CtrCipher cipher, IncrementalMac mac, int trailerLength, byte[][]? macPrefixParts = null)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        _mac = mac ?? throw new ArgumentNullException(nameof(mac));
        _trailerLength = trailerLength;

        if (macPrefixParts != null)
        {
            foreach (var part in macPrefixParts)
            {
                if (part != null && part.Length > 0)
                {
                    _mac.Append(part, 0, part.Length);
                }
            }
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

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (count <= 0) return;
        if (count > _work.Length)
        {
            // 大块：分段处理，避免大缓冲分配
            var remaining = count;
            var pos = offset;
            while (remaining > 0)
            {
                var chunk = Math.Min(remaining, _work.Length);
                Buffer.BlockCopy(buffer, pos, _work, 0, chunk);
                _cipher.Transform(_work, 0, chunk);
                _mac.Append(_work, 0, chunk); // Encrypt-then-MAC：HMAC 覆盖密文
                _sink.Write(_work, 0, chunk);
                pos += chunk;
                remaining -= chunk;
            }

            return;
        }

        Buffer.BlockCopy(buffer, offset, _work, 0, count);
        _cipher.Transform(_work, 0, count);
        _mac.Append(_work, 0, count); // Encrypt-then-MAC：HMAC 覆盖密文
        _sink.Write(_work, 0, count);
    }

    public override void Flush() => _sink.Flush();

    /// <summary>刷出 MAC 尾部并收底（不关闭底层流）。</summary>
    public void FinishTrailer()
    {
        if (_finished) return;
        _finished = true;

        var macOut = _mac.Final();
        var trailer = new byte[_trailerLength];
        Array.Copy(macOut, trailer, Math.Min(_trailerLength, macOut.Length));
        Array.Clear(macOut, 0, macOut.Length);
        _sink.Write(trailer, 0, trailer.Length);
        _sink.Flush();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            FinishTrailer();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// 读侧 CTR 解密流：底层流读取（仅 payload 长度）→ 增量 HMAC → CTR 解密 → 明文。
/// 读完 payload 后首次返回 0 前校验流尾认证码，失败抛 <see cref="ArchiveCorruptedException"/>。
/// </summary>
public class CtrReadStream : Stream
{
    private readonly Stream _source;
    private readonly CtrCipher _cipher;
    private readonly IncrementalMac _mac;
    private readonly long _payloadLength;
    private readonly int _trailerLength;
    private readonly byte[] _work = new byte[81920];
    private long _readPayload;
    private bool _validated;
    private bool _eof;

    public CtrReadStream(Stream source, CtrCipher cipher, IncrementalMac mac, long payloadLength, byte[][]? macPrefixParts = null, int? trailerLength = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        _mac = mac ?? throw new ArgumentNullException(nameof(mac));
        _payloadLength = payloadLength;
        _trailerLength = trailerLength ?? mac.MacSize;

        if (macPrefixParts != null)
        {
            foreach (var part in macPrefixParts)
            {
                if (part != null && part.Length > 0)
                {
                    _mac.Append(part, 0, part.Length);
                }
            }
        }
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _payloadLength;
    public override long Position { get => _readPayload; set => throw new NotSupportedException(); }
    public override bool CanTimeout => false;

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_eof) return ValidateAndFinish();

        var toRead = (int)Math.Min(count, _payloadLength - _readPayload);
        if (toRead <= 0)
        {
            return ValidateAndFinish();
        }

        var n = _source.Read(buffer, offset, toRead);
        if (n <= 0)
        {
            throw new ArchiveCorruptedException("Ciphertext data unexpectedly truncated");
        }

        _mac.Append(buffer, offset, n); // 先对原始密文做 MAC（buffer 即将被就地解密覆盖）
        _cipher.Transform(buffer, offset, n);
        _readPayload += n;

        // 消费者可能因 deflate 终结块而停止后续读取——payload 读完即刻校验认证码，
        // 避免"读不到尾部就永不校验"的假阴性。
        if (_readPayload >= _payloadLength)
        {
            ValidateAndFinish();
        }

        return n;
    }

    private int ValidateAndFinish()
    {
        if (_validated) return 0;
        _validated = true;
        _eof = true;

        var expected = _mac.Final();

        // 读取流尾认证码（截断长度由算法决定，如 WinZip AES 为 10 字节）
        var actual = new byte[_trailerLength];
        var total = 0;
        while (total < actual.Length)
        {
            var n = _source.Read(actual, total, actual.Length - total);
            if (n <= 0)
            {
                throw new ArchiveCorruptedException("HMAC trailer missing or truncated");
            }

            total += n;
        }

        if (!Kdf.FixedTimeEquals(expected, actual, _trailerLength))
        {
            throw new ArchiveCorruptedException("Integrity check failed (HMAC mismatch): data was tampered with or the password is wrong");
        }

        Array.Clear(expected, 0, expected.Length);
        Array.Clear(actual, 0, actual.Length);
        return 0;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
