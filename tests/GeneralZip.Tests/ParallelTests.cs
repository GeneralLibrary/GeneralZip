using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>并行压缩/解压与异步条目枚举测试。</summary>
public class ParallelTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");

    public ParallelTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static byte[] MakePayload(int size)
    {
        var data = new byte[size];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    private string MakeZip(int entryCount, int payloadSize = 100_000)
    {
        var zip = Path.Combine(_dir, $"src-{entryCount}-{payloadSize}.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            for (var i = 0; i < entryCount; i++)
            {
                var payload = MakePayload(payloadSize);
                w.AddStream($"data/file{i:D3}.bin", new MemoryStream(payload), payload.Length);
            }

            w.Finish();
        }

        return zip;
    }

    // ---------- 并行解压 ----------

    [Theory]
    [InlineData(8, 2)]
    [InlineData(16, 4)]
    public void ParallelExtract_SameResultAsSequential(int entryCount, int dop)
    {
        var zip = MakeZip(entryCount, 50_000);
        var outDir = Path.Combine(_dir, $"out-{dop}");

        var result = GeneralZip.Extract(zip, outDir, extraction: new ExtractionOptions
        {
            MaxDegreeOfParallelism = dop,
            OverwritePolicy = OverwritePolicy.Skip,
        });

        Assert.Equal(entryCount, result.ProcessedCount);
        var files = Directory.EnumerateFiles(outDir, "*", SearchOption.AllDirectories).ToList();
        Assert.Equal(entryCount, files.Count);
        foreach (var file in files)
        {
            Assert.Equal(50_000, new FileInfo(file).Length);
        }
    }

    [Fact]
    public void ParallelExtract_EncryptedWithPresetPassword()
    {
        var zip = Path.Combine(_dir, "enc-parallel.zip");
        var password = TestSecrets.NewPassword();
        using (var w = GeneralZipWriter.CreateNew(zip, o =>
        {
            o.EncryptionAlgorithm = "SM4-GM";
            o.Password = password;
        }))
        {
            for (var i = 0; i < 6; i++)
            {
                w.AddStream($"f{i}.bin", new MemoryStream(MakePayload(20_000)), 20_000);
            }

            w.Finish();
        }

        var outDir = Path.Combine(_dir, "enc-out");
        using (var r = GeneralZipReader.Open(zip, o => o.Password = password))
        {
            var result = r.ExtractToDirectory(outDir, new ExtractionOptions { MaxDegreeOfParallelism = 3 });
            Assert.Equal(6, result.ProcessedCount);
            Assert.Equal(0, result.Failures.Count);
        }

        // 每个文件都能按原样读回（大小一致）
        Assert.Equal(6, Directory.EnumerateFiles(outDir).Count(f => new FileInfo(f).Length == 20_000));
    }

    [Fact]
    public void ParallelExtract_RequiresPathOpen()
    {
        var zip = MakeZip(4, 10_000);
        using var stream = File.OpenRead(zip);
        using var r = GeneralZipReader.Open(stream);

        Assert.Throws<NotSupportedException>(() =>
            r.ExtractToDirectory(Path.Combine(_dir, "nope"), new ExtractionOptions { MaxDegreeOfParallelism = 2 }));
    }

    [Fact]
    public void ParallelExtract_TestAll()
    {
        var zip = MakeZip(8, 20_000);
        var result = GeneralZip.Test(zip);
        Assert.True(result.Success);

        using var r = GeneralZipReader.Open(zip);
        var parallel = r.TestAll(new ExtractionOptions { MaxDegreeOfParallelism = 3 });
        Assert.Equal(0, parallel.Failures.Count);
        Assert.Equal(8, parallel.ProcessedCount);
    }

    [Fact]
    public void ParallelExtract_EventsFire()
    {
        var zip = MakeZip(6, 30_000);
        var started = new List<string>();
        using var r = GeneralZipReader.Open(zip);
        r.EntryStarted += (_, e) => { lock (started) { started.Add(e.Entry.FullName); } };

        r.ExtractToDirectory(Path.Combine(_dir, "evt"), new ExtractionOptions { MaxDegreeOfParallelism = 3 });

        Assert.Equal(6, started.Count);
    }

    // ---------- 并行压缩（ZIP 分片模式） ----------

    [Fact]
    public void ParallelCompress_SameResultAsSequential()
    {
        var seqZip = Path.Combine(_dir, "seq.zip");
        var parZip = Path.Combine(_dir, "par.zip");
        var payloads = Enumerable.Range(0, 6).Select(_ => MakePayload(80_000)).ToList();

        using (var w = GeneralZipWriter.CreateNew(seqZip))
        {
            for (var i = 0; i < payloads.Count; i++)
            {
                w.AddStream($"f{i}.bin", new MemoryStream(payloads[i]), payloads[i].Length);
            }

            w.Finish();
        }

        using (var w = GeneralZipWriter.CreateNew(parZip, o => o.MaxDegreeOfParallelism = 3))
        {
            for (var i = 0; i < payloads.Count; i++)
            {
                w.AddStream($"f{i}.bin", new MemoryStream(payloads[i]), payloads[i].Length);
            }

            w.Finish();
        }

        // 逐条目内容一致（压缩参数相同 → 字节级一致）
        using (var a = GeneralZipReader.Open(seqZip))
        using (var b = GeneralZipReader.Open(parZip))
        {
            Assert.Equal(a.Entries.Count, b.Entries.Count);
            for (var i = 0; i < a.Entries.Count; i++)
            {
                Assert.Equal(a.Entries[i].FullName, b.Entries[i].FullName);
                Assert.Equal(a.Entries[i].Size, b.Entries[i].Size);
                Assert.Equal(a.Entries[i].Crc32, b.Entries[i].Crc32);
                Assert.Equal(a.Entries[i].CompressedSize, b.Entries[i].CompressedSize);
            }
        }
    }

    [Fact]
    public void ParallelCompress_EncryptedRoundtrip()
    {
        var zip = Path.Combine(_dir, "par-enc.zip");
        var password = TestSecrets.NewPassword();
        var payload = MakePayload(120_000);

        using (var w = GeneralZipWriter.CreateNew(zip, o =>
        {
            o.MaxDegreeOfParallelism = 2;
            o.EncryptionAlgorithm = "SM4-GM";
            o.Password = password;
        }))
        {
            for (var i = 0; i < 4; i++)
            {
                w.AddStream($"e{i}.bin", new MemoryStream(payload), payload.Length);
            }

            w.Finish();
        }

        var result = GeneralZip.Test(zip, o => o.Password = password);
        Assert.True(result.Success);

        using var r = GeneralZipReader.Open(zip, o => o.Password = password);
        using var s = r.OpenEntryStream(r.Entries[2]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());
    }

    [Fact]
    public void ParallelCompress_ErrorPropagates()
    {
        var zip = Path.Combine(_dir, "par-err.zip");
        using var w = GeneralZipWriter.CreateNew(zip, o => o.MaxDegreeOfParallelism = 2);
        w.AddStream("ok.bin", new MemoryStream(MakePayload(50_000)), 50_000);
        // 分片模式在 AddEntry 即捕获明文：坏流在此时抛出
        Assert.Throws<IOException>(() => w.AddStream("bad.bin", new ThrowingStream()));
    }

    private sealed class ThrowingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;

        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("boom");
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    }

    // ---------- IAsyncEnumerable ----------

    [Fact]
    public async Task EnumerateEntriesAsync_YieldsAll()
    {
        var zip = MakeZip(5, 10_000);
        using var r = GeneralZipReader.Open(zip);

        var names = new List<string>();
        await foreach (var entry in r.EnumerateEntriesAsync())
        {
            names.Add(entry.FullName);
        }

        Assert.Equal(5, names.Count);
        Assert.Contains("data/file002.bin", names);
    }

    [Fact]
    public async Task EnumerateEntriesAsync_Cancellation()
    {
        var zip = MakeZip(5, 10_000);
        using var r = GeneralZipReader.Open(zip);
        using var cts = new CancellationTokenSource();

        var count = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var entry in r.EnumerateEntriesAsync(cts.Token))
            {
                count++;
                if (count >= 2)
                {
                    await cts.CancelAsync();
                }
            }
        });
        Assert.Equal(2, count);
    }
}
