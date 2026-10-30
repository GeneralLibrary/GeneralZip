using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;
using static GeneralZip.GeneralZip;

namespace GeneralZip.Tests;

/// <summary>TAR 族与单文件编解码格式测试。</summary>
public class FormatTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-fmt-{Guid.NewGuid():N}");

    public FormatTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void Tar_Roundtrip()
    {
        var tar = Path.Combine(_dir, "a.tar");
        using (var w = GeneralZipWriter.CreateNew(tar))
        {
            var payload = Encoding.UTF8.GetBytes("tar 内容");
            w.AddStream("dir/hello.txt", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(tar);
        Assert.Equal("TAR", r.Format.Name);
        Assert.True(r.Entries.Count >= 1);
        using var s = r.OpenEntryStream(r.Entries.First(e => e.FullName == "dir/hello.txt"));
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("tar 内容", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void TarGz_SignatureDetects_And_Roundtrip()
    {
        var tgz = Path.Combine(_dir, "b.tar.gz");
        using (var w = GeneralZipWriter.CreateNew(tgz))
        {
            w.AddStream("x.txt", new MemoryStream(new byte[10000]), 10000);
            w.Finish();
        }

        // 自动探测（tar.gz 与单文件 gz 都有 gzip 魔数，靠解压后 ustar 魔数区分）
        using var r = GeneralZipReader.Open(tgz);
        Assert.Equal("TAR.GZ", r.Format.Name);

        var dest = Path.Combine(_dir, "out-tgz");
        r.ExtractToDirectory(dest);
        Assert.Equal(10000, new FileInfo(Path.Combine(dest, "x.txt")).Length);
    }

    [Fact]
    public void Gzip_SingleFile_Roundtrip()
    {
        var gz = Path.Combine(_dir, "single.txt.gz");
        var payload = Encoding.UTF8.GetBytes("single file gzip 内容");

        using (var w = GeneralZipWriter.CreateNew(gz))
        {
            w.AddStream("single.txt", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(gz);
        Assert.Equal("GZIP", r.Format.Name);
        Assert.Equal("single.txt", r.Entries[0].FullName); // 从文件名剥扩展名
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());
    }

    // 说明：BZ2/XZ/ZSTD/LZ4 编解码自本版本起经 Rust 原生核心实现，
    // 相关测试移至 GeneralZip.Native.Tests（核心缺失时跳过）。

    [Fact]
    public void CompressDirectory_OneLiner_And_Detect()
    {
        var src = Path.Combine(_dir, "proj");
        Directory.CreateDirectory(src);
        File.WriteAllText(Path.Combine(src, "a.txt"), "aaa");
        File.WriteAllText(Path.Combine(src, "b.txt"), "bbb");

        var zip = Path.Combine(_dir, "proj.zip");
        Compress(src, zip);

        Assert.Equal("ZIP", DetectFormat(zip)?.Name);

        var dest = Path.Combine(_dir, "restore");
        var result = Extract(zip, dest);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal("aaa", File.ReadAllText(Path.Combine(dest, "proj", "a.txt")));
    }

    [Fact]
    public void UnsupportedFormat_Throws()
    {
        var fake = Path.Combine(_dir, "fake.bin");
        File.WriteAllBytes(fake, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A });

        Assert.Throws<UnsupportedFormatException>(() => GeneralZipReader.Open(fake));
    }

    [Fact]
    public void GzipBytes_FromSystemIo_Compatible()
    {
        // System.IO.Compression 产出的 gzip → 本组件读取（生态互操作）
        var gz = Path.Combine(_dir, "sys.gz");
        var payload = Encoding.UTF8.GetBytes("system gzip 写入，GeneralZip 读取");
        using (var fs = new FileStream(gz, FileMode.Create))
        using (var gzStream = new GZipStream(fs, CompressionLevel.Optimal))
        {
            gzStream.Write(payload, 0, payload.Length);
        }

        using var r = GeneralZipReader.Open(gz, o => o.SourceName = "sys.txt.gz");
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());
    }
}
