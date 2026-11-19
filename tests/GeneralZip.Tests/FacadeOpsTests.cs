using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>门面高阶操作测试：追加/删除/转换（重写语义）、Stream→Stream、Glob 过滤。</summary>
public class FacadeOpsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");

    public FacadeOpsTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string MakeFile(string relativePath, string content)
    {
        var path = Path.Combine(_dir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }

    // ---------- Append ----------

    [Fact]
    public void Append_FileAndDirectory_ExistingEntriesPreserved()
    {
        var zip = Path.Combine(_dir, "append.zip");
        var srcDir = Path.Combine(_dir, "srcdir");
        Directory.CreateDirectory(srcDir);
        File.WriteAllText(Path.Combine(srcDir, "n1.txt"), "n1");
        Directory.CreateDirectory(Path.Combine(srcDir, "sub"));
        File.WriteAllText(Path.Combine(srcDir, "sub", "n2.txt"), "n2");

        GeneralZip.Compress(MakeFile("a.txt", "AAA"), zip);

        GeneralZip.Append(zip, MakeFile("b.txt", "BBB"));
        GeneralZip.Append(zip, srcDir);

        using var r = GeneralZipReader.Open(zip);
        var names = r.Entries.Select(e => e.FullName).OrderBy(n => n).ToList();
        Assert.Contains("a.txt", names);
        Assert.Contains("b.txt", names);
        Assert.Contains("srcdir/n1.txt", names);
        Assert.Contains("srcdir/sub/", names);
        Assert.Contains("srcdir/sub/n2.txt", names);
        Assert.Equal(5, r.Entries.Count);

        using var stream = r.OpenEntryStream(r.Entries.First(e => e.FullName == "a.txt"));
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        Assert.Equal("AAA", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Append_EncryptedInheritsAlgorithm()
    {
        var zip = Path.Combine(_dir, "enc-append.zip");
        var password = TestSecrets.NewPassword();

        GeneralZip.Compress(MakeFile("secret1.txt", "S1"), zip, o =>
        {
            o.EncryptionAlgorithm = "SM4-GM";
            o.Password = password;
        });

        // 只给口令、不给算法 → 继承源归档的 SM4-GM
        GeneralZip.Append(zip, MakeFile("secret2.txt", "S2"), o => o.Password = password);

        using var r = GeneralZipReader.Open(zip, o => o.Password = password);
        Assert.True(r.IsEncrypted);
        foreach (var entry in r.Entries.Where(e => !e.IsDirectory))
        {
            Assert.Equal("SM4-GM", entry.EncryptionAlgorithm);
        }

        using var s = r.OpenEntryStream(r.Entries.First(e => e.FullName == "secret2.txt"));
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("S2", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Append_TarGzRoundtrip()
    {
        var tarGz = Path.Combine(_dir, "app.tar.gz");
        GeneralZip.Compress(MakeFile("x.txt", "X"), tarGz);
        GeneralZip.Append(tarGz, MakeFile("y.txt", "Y"));

        using var r = GeneralZipReader.Open(tarGz);
        Assert.Equal(2, r.Entries.Count);
        Assert.Equal("TAR.GZ", r.Format.Name);
    }

    // ---------- Remove ----------

    [Fact]
    public void Remove_ByNames()
    {
        var zip = Path.Combine(_dir, "rm.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("keep1.txt", new MemoryStream(Encoding.UTF8.GetBytes("1")), 1);
            w.AddStream("drop.txt", new MemoryStream(Encoding.UTF8.GetBytes("2")), 1);
            w.AddStream("keep2.txt", new MemoryStream(Encoding.UTF8.GetBytes("3")), 1);
            w.Finish();
        }

        GeneralZip.Remove(zip, new[] { "drop.txt" });

        using var r = GeneralZipReader.Open(zip);
        var names = r.Entries.Select(e => e.FullName).ToList();
        Assert.Equal(new[] { "keep1.txt", "keep2.txt" }, names);
    }

    [Fact]
    public void Remove_ByPredicate()
    {
        var zip = Path.Combine(_dir, "rm-pred.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("a/tmp/x.tmp", new MemoryStream(Encoding.UTF8.GetBytes("t")), 1);
            w.AddStream("b/main.txt", new MemoryStream(Encoding.UTF8.GetBytes("m")), 1);
            w.Finish();
        }

        GeneralZip.Remove(zip, predicate: e => e.FullName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase));

        using var r = GeneralZipReader.Open(zip);
        Assert.Single(r.Entries);
        Assert.Equal("b/main.txt", r.Entries[0].FullName);
    }

    // ---------- Convert ----------

    [Fact]
    public void Convert_ZipToTarGz_AndBack()
    {
        var zip = Path.Combine(_dir, "conv.zip");
        var tarGz = Path.Combine(_dir, "conv.tar.gz");
        var zip2 = Path.Combine(_dir, "conv2.zip");

        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("dir/a.txt", new MemoryStream(Encoding.UTF8.GetBytes("AAA")), 3, new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero));
            w.AddStream("dir/b.bin", new MemoryStream(new byte[] { 1, 2, 3, 4 }), 4);
            w.AddDirectoryEntry("dir/empty");
            w.Finish();
        }

        GeneralZip.Convert(zip, tarGz);
        Assert.Equal("TAR.GZ", GeneralZip.DetectFormat(tarGz)?.Name);

        using (var r1 = GeneralZipReader.Open(tarGz))
        {
            Assert.Equal(3, r1.Entries.Count);
            Assert.Equal(2020, r1.Entries[0].LastWriteTime?.UtcDateTime.Year);
        }

        GeneralZip.Convert(tarGz, zip2);
        using (var r2 = GeneralZipReader.Open(zip2))
        {
            using var s = r2.OpenEntryStream(r2.Entries.First(e => e.FullName == "dir/a.txt"));
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            Assert.Equal("AAA", Encoding.UTF8.GetString(ms.ToArray()));
        }
    }

    [Fact]
    public void Convert_ToEncryptedZip()
    {
        var tarGz = Path.Combine(_dir, "plain.tar.gz");
        var zipEnc = Path.Combine(_dir, "target.zip");
        var password = TestSecrets.NewPassword();
        GeneralZip.Compress(MakeFile("m.txt", "M"), tarGz);

        GeneralZip.Convert(tarGz, zipEnc, o =>
        {
            o.EncryptionAlgorithm = "WinZipAES256";
            o.Password = password;
        });

        var result = GeneralZip.Test(zipEnc, o => o.Password = password);
        Assert.True(result.Success);
    }

    // ---------- Stream → Stream ----------

    [Fact]
    public async Task StreamApi_CompressExtract_Test_Zip()
    {
        var payload = Encoding.UTF8.GetBytes("stream roundtrip 中文 0123456789");

        using var outMs = new MemoryStream();
        await GeneralZip.CompressAsync(new MemoryStream(payload), outMs, "ZIP", "data/payload.txt");

        outMs.Position = 0;
        var info = GeneralZip.DetectFormat(outMs);
        Assert.Equal("ZIP", info?.Name);

        outMs.Position = 0;
        using (var r = GeneralZipReader.Open(outMs))
        {
            Assert.Single(r.Entries);
            Assert.Equal("data/payload.txt", r.Entries[0].FullName);
        }

        outMs.Position = 0;
        var extractDir = Path.Combine(_dir, "stream-out");
        var result = await GeneralZip.ExtractAsync(outMs, extractDir);
        Assert.Equal(1, result.ProcessedCount);
        Assert.Equal("stream roundtrip 中文 0123456789",
            File.ReadAllText(Path.Combine(extractDir, "data", "payload.txt"), Encoding.UTF8));

        outMs.Position = 0;
        var test = GeneralZip.Test(outMs);
        Assert.True(test.Success);
    }

    [Fact]
    public async Task StreamApi_GzipSingleFileSemantics()
    {
        using var outMs = new MemoryStream();
        await GeneralZip.CompressAsync(new MemoryStream(new byte[] { 9, 9, 9 }), outMs, "GZIP", "named.bin");

        outMs.Position = 0;
        using var r = GeneralZipReader.Open(outMs);
        // 单文件编解码格式（GZIP）不保存条目名：流式入口无源名时条目名为 "content"
        Assert.Equal("content", r.Entries[0].FullName);
        using var s = r.OpenEntryStream(r.Entries[0]);
        var buf = new byte[3];
        Assert.Equal(3, ReadFull(s, buf));
    }

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

    // ---------- Glob 过滤 ----------

    [Fact]
    public void GlobFilter_IncludeExclude()
    {
        var zip = Path.Combine(_dir, "glob.zip");
        var outDir = Path.Combine(_dir, "glob-out");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("photos/a.jpg", new MemoryStream(new byte[] { 1 }), 1);
            w.AddStream("photos/nested/b.jpg", new MemoryStream(new byte[] { 2 }), 1);
            w.AddStream("docs/readme.txt", new MemoryStream(new byte[] { 3 }), 1);
            w.AddStream("docs/tmp/cache.tmp", new MemoryStream(new byte[] { 4 }), 1);
            w.Finish();
        }

        GeneralZip.Extract(zip, outDir, extraction: new ExtractionOptions
        {
            IncludePatterns = new[] { "photos/**/*.jpg" },
            ExcludePatterns = new[] { "**/*.tmp" },
        });

        var files = Directory.EnumerateFiles(outDir, "*", SearchOption.AllDirectories)
            .Select(Path.GetFileName).OrderBy(n => n).ToList();
        Assert.Equal(new[] { "a.jpg", "b.jpg" }, files);
    }

    [Theory]
    [InlineData("a/b/c.jpg", "a/**/c.jpg", true)]
    [InlineData("a/c.jpg", "a/**/c.jpg", true)]
    [InlineData("a/b/c.jpg", "*/c.jpg", false)]
    [InlineData("a/b/c.jpg", "**/c.jpg", true)]
    [InlineData("c.jpg", "**/c.jpg", true)]
    [InlineData("root/x.tmp", "*.tmp", false)]
    [InlineData("x.tmp", "*.tmp", true)]
    [InlineData("sub/x.tmp", "**/*.tmp", true)]
    [InlineData("file.TXT", "*.txt", true)]
    [InlineData("log2024.txt", "log[0-9]*.txt", true)]
    [InlineData("logx.txt", "log[0-9]*.txt", false)]
    [InlineData("a?b.txt", "a?b.txt", true)]
    public void GlobMatcher_Matrices(string path, string pattern, bool expected)
    {
        Assert.Equal(expected, global::GeneralZip.GlobMatcher.IsMatch(path, pattern));
    }
}
