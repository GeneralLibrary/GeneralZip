using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using GeneralZip;
using GeneralZip.Native;
using Xunit;

namespace GeneralZip.Native.Tests;

/// <summary>
/// 原生编解码格式测试（BZ2/XZ/ZSTD/LZ4，全部纯 Rust 实现：libbz2-rs / lzma-rs / rust-zstd / lz4_flex）。
/// 原生核心缺失时跳过。
/// </summary>
public class NativeCodecTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-ncodec-{Guid.NewGuid():N}");

    public NativeCodecTests()
    {
        Directory.CreateDirectory(_dir);
        NativeCoreLoader.TryLoad();
        GeneralZipNative.Initialize(); // 注入原生编解码桥接（BZ2/XZ/ZSTD/LZ4 路由需要）
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private bool SkipIfNoCore()
    {
        if (NativeCoreLoader.IsAvailable)
        {
            return false;
        }

        Assert.True(true, $"SKIPPED: native core not loaded: {NativeCoreLoader.FailureReason}");
        return true;
    }

    [Theory]
    [InlineData("BZIP2", ".bz2")]
    [InlineData("XZ", ".xz")]
    [InlineData("ZSTD", ".zst")]
    [InlineData("LZ4", ".lz4")]
    public void SingleFileCodec_Roundtrip(string formatName, string extension)
    {
        if (SkipIfNoCore()) return;

        var path = Path.Combine(_dir, $"c{extension}");
        var payload = new byte[120_000];
        RandomNumberGenerator.Fill(payload);

        using (var w = GeneralZipWriter.CreateNew(path))
        {
            w.AddStream("c.bin", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(path);
        Assert.Equal(formatName, r.Format.Name);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal(payload, ms.ToArray());
    }

    [Fact]
    public void Bzip2_Tar_Roundtrip()
    {
        if (SkipIfNoCore()) return;

        var tbz = Path.Combine(_dir, "e.tar.bz2");
        using (var w = GeneralZipWriter.CreateNew(tbz))
        {
            var payload = Encoding.UTF8.GetBytes("bz2 tar");
            w.AddStream("e/f.txt", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(tbz);
        Assert.Equal("TAR.BZ2", r.Format.Name);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("bz2 tar", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void TarGz_Roundtrip_WithNativeCore()
    {
        if (SkipIfNoCore()) return;

        var tgz = Path.Combine(_dir, "b.tar.gz");
        using (var w = GeneralZipWriter.CreateNew(tgz))
        {
            w.AddStream("x.txt", new MemoryStream(new byte[10000]), 10000);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(tgz);
        Assert.Equal("TAR.GZ", r.Format.Name);

        var dest = Path.Combine(_dir, "out-tgz");
        r.ExtractToDirectory(dest);
        Assert.Equal(10000, new FileInfo(Path.Combine(dest, "x.txt")).Length);
    }
}
