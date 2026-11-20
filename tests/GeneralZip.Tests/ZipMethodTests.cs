using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Cryptography;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>
/// ZIP 扩展压缩方法（BZip2/Zstd/LZMA）与全部原生单文件编解码测试。
/// 依赖 Rust 原生核心；核心缺失时跳过（与 NativeCoreTests.SkipIfNoCore 同模式）。
/// </summary>
public class ZipMethodTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");
    private static readonly bool HasCore = global::GeneralZip.Formats.Codecs.NativeCodecRouter.IsCoreAvailable();

    public ZipMethodTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static bool SkipIfNoCore()
    {
        if (HasCore)
        {
            return false;
        }

        Assert.True(true, "SKIPPED: native core not loaded");
        return true;
    }

    private static byte[] MakePayload(int size)
    {
        // 半可压缩数据：重复块 + 随机尾，验证真实压缩路径（测试数据，非密钥材料）
        var data = new byte[size];
        var chunk = new byte[4096];
        RandomNumberGenerator.Fill(chunk);
        for (var i = 0; i < size; i += chunk.Length)
        {
            Buffer.BlockCopy(chunk, 0, data, i, Math.Min(chunk.Length, size - i));
        }

        return data;
    }

    [Theory]
    [InlineData(ZipCompressionMethodChoice.BZip2)]
    [InlineData(ZipCompressionMethodChoice.Zstd)]
    [InlineData(ZipCompressionMethodChoice.Lzma)]
    public void ZipMethod_Roundtrip(ZipCompressionMethodChoice method)
    {
        if (SkipIfNoCore()) return;

        var zip = Path.Combine(_dir, $"{method}.zip");
        var payload = MakePayload(300_000);

        using (var w = GeneralZipWriter.CreateNew(zip, o => o.ZipCompressionMethod = method))
        {
            w.AddStream("data.bin", new MemoryStream(payload), payload.Length);
            w.AddStream("empty.bin", new MemoryStream(Array.Empty<byte>()), 0); // 空条目强制 Store
            w.AddStream("text.txt", new MemoryStream(Encoding.UTF8.GetBytes(new string('a', 5000))), 5000);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        Assert.Equal(3, r.Entries.Count);
        using (var s = r.OpenEntryStream(r.Entries[0]))
        using (var ms = new MemoryStream())
        {
            s.CopyTo(ms);
            Assert.Equal(payload, ms.ToArray());
        }

        // 压缩确实生效
        Assert.True(r.Entries[0].CompressedSize < payload.Length, $"{method} should compress");
    }

    [Theory]
    [InlineData(ZipCompressionMethodChoice.BZip2, "SM4-GM")]
    [InlineData(ZipCompressionMethodChoice.Zstd, "WinZipAES256")]
    [InlineData(ZipCompressionMethodChoice.Lzma, "SM2-GM")]
    public void ZipMethod_EncryptedRoundtrip(ZipCompressionMethodChoice method, string algorithm)
    {
        if (SkipIfNoCore()) return;

        var zip = Path.Combine(_dir, $"{method}-{algorithm}.zip");
        var payload = MakePayload(200_000);

        string password;
        string? publicKey = null;
        if (algorithm == "SM2-GM")
        {
            var keyPair = Sm2KeyPair.Generate();
            publicKey = keyPair.PublicKeyHex;
            password = keyPair.PrivateKeyHex;
        }
        else
        {
            password = TestSecrets.NewPassword();
        }

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
        {
            o.ZipCompressionMethod = method;
            o.EncryptionAlgorithm = algorithm;
            o.Password = algorithm == "SM2-GM" ? null : password;
            o.RecipientPublicKey = publicKey;
        }))
        {
            w.AddStream("enc.bin", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip, o => o.Password = password);
        Assert.True(r.IsEncrypted);
        using (var s = r.OpenEntryStream(r.Entries[0]))
        using (var ms = new MemoryStream())
        {
            s.CopyTo(ms);
            Assert.Equal(payload, ms.ToArray());
        }

        var test = GeneralZip.Test(zip, o => o.Password = password);
        Assert.True(test.Success);
    }

    [Theory]
    [InlineData("BZIP2", ".bz2")]
    [InlineData("XZ", ".xz")]
    [InlineData("ZSTD", ".zst")]
    [InlineData("LZ4", ".lz4")]
    [InlineData("BROTLI", ".br")]
    public void SingleFileCodec_Roundtrip(string formatName, string extension)
    {
        if (SkipIfNoCore()) return;

        var path = Path.Combine(_dir, $"sample{extension}");
        var payload = MakePayload(150_000);

        using (var w = GeneralZipWriter.CreateNew(path, configure: null, formatName))
        {
            w.AddStream("content", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        // 流对象保持打开（所有权契约）：读取后调用方流仍可用
        using (var fs = File.OpenRead(path))
        {
            using var r = GeneralZipReader.Open(fs, formatName);
            using (var s = r.OpenEntryStream(r.Entries[0]))
            using (var ms = new MemoryStream())
            {
                s.CopyTo(ms);
                Assert.Equal(payload, ms.ToArray());
            }
        }

        // 路径入口（含 SourceName 推导）
        using (var r = GeneralZipReader.Open(path))
        {
            Assert.Equal("sample", r.Entries[0].FullName);
        }
    }

    [Fact]
    public void SingleFileCodec_RejectsSecondEntry()
    {
        var gzip = Path.Combine(_dir, "single.gz");
        using var writer = GeneralZipWriter.CreateNew(gzip, formatName: "GZIP");
        writer.AddStream("first", new MemoryStream(new byte[] { 1 }), 1);
        Assert.Throws<NotSupportedException>(() =>
            writer.AddStream("second", new MemoryStream(new byte[] { 2 }), 1));
    }

    [Fact]
    public void Zstd_Streaming_LargeFile()
    {
        if (SkipIfNoCore()) return;

        // 大文件流式压缩：验证压缩直通（不再有一次性内存缓冲/临时密文副本）
        var src = Path.Combine(_dir, "big.bin");
        var dst = Path.Combine(_dir, "big.zst");
        var totalBytes = 8L * 1024 * 1024;
        var chunk = new byte[8192];
        using (var fs = File.Create(src))
        {
            for (long written = 0; written < totalBytes; written += chunk.Length)
            {
                RandomNumberGenerator.Fill(chunk);
                fs.Write(chunk, 0, chunk.Length);
            }
        }

        using (var output = File.Create(dst))
        using (var input = File.OpenRead(src))
        {
            global::GeneralZip.Formats.Codecs.NativeCodecRouter.CompressStream(input, output, "zstd", 6, CancellationToken.None);
        }

        Assert.True(new FileInfo(dst).Length > 0);

        using (var input = File.OpenRead(dst))
        {
            using var r = GeneralZipReader.Open(input, "ZSTD");
            long drained = 0;
            using (var s = r.OpenEntryStream(r.Entries[0]))
            {
                var buffer = new byte[81920];
                int n;
                while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
                {
                    drained += n;
                }
            }

            Assert.Equal(totalBytes, drained);
        }
    }

    [Fact]
    public void ZipMethod_Cancellation_Aborts()
    {
        if (SkipIfNoCore()) return;

        using var cts = new CancellationTokenSource();
        var payload = MakePayload(2_000_000);
        var src = new MemoryStream(payload);
        var dst = new MemoryStream();
        cts.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            global::GeneralZip.Formats.Codecs.NativeCodecRouter.CompressStream(src, dst, "zstd", 6, cts.Token));
    }
}
