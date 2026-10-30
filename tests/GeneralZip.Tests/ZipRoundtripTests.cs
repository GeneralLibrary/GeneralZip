using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>ZIP 引擎往返测试（自写自读 + 加密矩阵）。</summary>
public class ZipRoundtripTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");

    public ZipRoundtripTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Theory]
    [InlineData(CompressionLevelChoice.NoCompression)]
    [InlineData(CompressionLevelChoice.Fastest)]
    [InlineData(CompressionLevelChoice.Optimal)]
    public void Roundtrip_DeflateLevels(CompressionLevelChoice level)
    {
        var zip = Path.Combine(_dir, $"lv-{level}.zip");
        var payload = Encoding.UTF8.GetBytes("压缩往返测试 GeneralZip 中文内容 data 0123456789");

        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("a/中文文件.txt", new MemoryStream(payload), payload.Length);
            w.AddStream("b/empty.bin", new MemoryStream(Array.Empty<byte>()), 0);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        Assert.Equal(2, r.Entries.Count);
        Assert.Equal("a/中文文件.txt", r.Entries[0].FullName);

        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());

        using var s2 = r.OpenEntryStream(r.Entries[1]);
        Assert.Equal(0, s2.Length);
    }

    [Fact]
    public void Roundtrip_AddDirectory()
    {
        var src = Path.Combine(_dir, "src");
        Directory.CreateDirectory(Path.Combine(src, "sub", "deep"));
        File.WriteAllText(Path.Combine(src, "root.txt"), "root");
        File.WriteAllText(Path.Combine(src, "sub", "inner.txt"), "inner");
        File.WriteAllText(Path.Combine(src, "sub", "deep", "leaf.bin"), new string('L', 50000));

        var zip = Path.Combine(_dir, "dirs.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddDirectory(src, "backup");
            w.Finish();
        }

        var dest = Path.Combine(_dir, "out");
        using var r = GeneralZipReader.Open(zip);
        var result = r.ExtractToDirectory(dest);

        Assert.Equal(3, result.ProcessedCount);
        Assert.Equal("root", File.ReadAllText(Path.Combine(dest, "backup", "root.txt")));
        Assert.Equal("inner", File.ReadAllText(Path.Combine(dest, "backup", "sub", "inner.txt")));
        Assert.Equal(50000, File.ReadAllText(Path.Combine(dest, "backup", "sub", "deep", "leaf.bin")).Length);
    }

    [Fact]
    public void Roundtrip_StreamWithoutSeek()
    {
        // 不可寻址源流 + 未知大小（数据描述符路径）
        var zip = Path.Combine(_dir, "nonseek.zip");
        var payload = Encoding.UTF8.GetBytes(new string('S', 123456));

        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            var stream = new NonSeekableWrapper(new MemoryStream(payload));
            w.AddStream("blob.bin", stream, size: null);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());
    }

    [Fact]
    public void StreamDestination_NonSeekableOutput()
    {
        var zip = Path.Combine(_dir, "out-stream.zip");
        using (var fs = new FileStream(zip, FileMode.Create, FileAccess.Write))
        using (var w = GeneralZipWriter.CreateNew(fs, formatName: "ZIP"))
        {
            var payload = Encoding.UTF8.GetBytes("非寻址输出");
            w.AddStream("x.txt", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        Assert.Single(r.Entries);
    }

    // ---------- 加密矩阵 ----------

    [Theory]
    [InlineData("WinZipAES256")]
    [InlineData("WinZipAES128")]
    [InlineData("ZipCrypto")]
    [InlineData("SM4-GM")]
    public void EncryptedRoundtrip_AllAlgorithms(string algorithm)
    {
        var zip = Path.Combine(_dir, "enc-" + algorithm + ".zip");
        var password = TestSecrets.Fixed(algorithm.Length);
        var payload = Encoding.UTF8.GetBytes($"加密往返 {algorithm} 机密数据 confidential");

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
               {
                   o.EncryptionAlgorithm = algorithm;
                   o.Password = password;
                   o.AllowWeakZipCrypto = algorithm == "ZipCrypto";
               }))
        {
            w.AddStream("secret/data.txt", new MemoryStream(payload), payload.Length);
            w.AddStream("secret/empty.txt", new MemoryStream(Array.Empty<byte>()), 0);
            w.Finish();
        }

        // 错误口令 → 快速失败（AES/SM4 校验值；ZipCrypto 头部校验字节）
        using (var r = GeneralZipReader.Open(zip, o => o.Password = TestSecrets.Wrong(password)))
        {
            Assert.True(r.IsEncrypted);
            Assert.Throws<InvalidPasswordException>(() =>
            {
                using var s = r.OpenEntryStream(r.Entries[0]);
                var sink = new byte[64];
                s.Read(sink, 0, sink.Length);
            });
        }

        // 正确口令 → 完整读出
        using (var r = GeneralZipReader.Open(zip, o => o.Password = password))
        {
            using var s = r.OpenEntryStream(r.Entries[0]);
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            Assert.Equal(payload, ms.ToArray());

            using var s2 = r.OpenEntryStream(r.Entries[1]);
            Assert.Equal(0, s2.Length);
        }
    }

    [Theory]
    [InlineData("WinZipAES256")]
    [InlineData("SM4-GM")]
    public void EncryptedTamperDetection_HmacRejects(string algorithm)
    {
        var zip = Path.Combine(_dir, $"tamper-{algorithm}.zip");
        var password = TestSecrets.Fixed(algorithm.Length + 1);
        using (var w = GeneralZipWriter.CreateNew(zip, o =>
               {
                   o.EncryptionAlgorithm = algorithm;
                   o.Password = password;
               }))
        {
            w.AddStream("t.bin", new MemoryStream(new byte[2048]), 2048);
            w.Finish();
        }

        // 篡改条目数据区（第一个 local header 之后 10 字节处，必落在密文/压缩数据内）
        var bytes = File.ReadAllBytes(zip);
        var nameLen = bytes[26] | (bytes[27] << 8);
        var extraLen = bytes[28] | (bytes[29] << 8);
        var dataStart = 30 + nameLen + extraLen;
        bytes[dataStart + 10] ^= 0xFF;
        var tampered = Path.Combine(_dir, $"tampered-{algorithm}.zip");
        File.WriteAllBytes(tampered, bytes);

        var detected = false;
        try
        {
            using var r = GeneralZipReader.Open(tampered, o => o.Password = password);
            using var s = r.OpenEntryStream(r.Entries[0]);
            using var ms = new MemoryStream();
            s.CopyTo(ms);
        }
        catch (ArchiveException)
        {
            detected = true;
        }

        Assert.True(detected, "Tampered encrypted archive must be rejected by integrity checks");
    }

    [Fact]
    public void ZipCrypto_Write_RequiresExplicitOptIn()
    {
        var zip = Path.Combine(_dir, "weak.zip");
        Assert.Throws<NotSupportedException>(() =>
        {
            using var w = GeneralZipWriter.CreateNew(zip, o =>
            {
                o.EncryptionAlgorithm = "ZipCrypto";
                o.Password = TestSecrets.Fixed(7);
            });
        });
    }

    [Fact]
    public void LargeFile_Roundtrip_1MB()
    {
        var zip = Path.Combine(_dir, "large.zip");
        var password = TestSecrets.NewPassword();
        var payload = new byte[1024 * 1024];
        RandomNumberGenerator.Fill(payload);

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
               {
                   o.EncryptionAlgorithm = "SM4-GM";
                   o.Password = password;
               }))
        {
            w.AddStream("big.bin", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip, o => o.Password = password);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());
    }

    [Fact]
    public void TestAll_ValidatesCrc()
    {
        var zip = Path.Combine(_dir, "crc.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("ok.txt", new MemoryStream(Encoding.UTF8.GetBytes("healthy")), 7);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        var result = r.TestAll();
        Assert.Equal(0, result.FailedCount);
    }

    [Fact]
    public void UnsafeEntryPaths_Rejected()
    {
        var zip = Path.Combine(_dir, "evil.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("../escape.txt", new MemoryStream(Encoding.UTF8.GetBytes("evil")), 4);
            w.Finish();
        }

        var dest = Path.Combine(_dir, "out-evil");
        using var r = GeneralZipReader.Open(zip);
        var result = r.ExtractToDirectory(dest, new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll });

        Assert.Equal(1, result.FailedCount);
        Assert.False(File.Exists(Path.Combine(_dir, "escape.txt")));
    }

    private sealed class NonSeekableWrapper : Stream
    {
        private readonly MemoryStream _inner;

        public NonSeekableWrapper(MemoryStream inner) => _inner = inner;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
