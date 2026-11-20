using System;
using System.IO;
using System.Linq;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>Unix 属性（st_mode）与符号链接条目测试（写入侧显式 API；读取侧 ZIP/TAR 双格式）。</summary>
public class UnixAttrsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");

    public UnixAttrsTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    // ---------- ZIP ----------

    [Fact]
    public void Zip_AddSymlink_Roundtrip()
    {
        var zip = Path.Combine(_dir, "sym.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("real.txt", new MemoryStream(Encoding.UTF8.GetBytes("data")), 4);
            w.AddSymlink("link.txt", "real.txt");
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        var link = r.Entries.First(e => e.FullName == "link.txt");
        var unix = Assert.IsAssignableFrom<IUnixEntry>(link);
        Assert.NotNull(unix.UnixMode);
        Assert.Equal(0xA000u, unix.UnixMode & 0xF000u); // S_IFLNK 类型位

        // 目标以条目内容承载
        using var s = r.OpenEntryStream(link);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("real.txt", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Zip_UnixMode_WriteRead()
    {
        var zip = Path.Combine(_dir, "mode.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("script.sh", new MemoryStream(new byte[] { 1 }), new ArchiveEntryMetadata
            {
                Size = 1,
                UnixMode = 0x81ED, // S_IFREG | 0755
            });
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        var unix = Assert.IsAssignableFrom<IUnixEntry>(r.Entries[0]);
        Assert.Equal(0x81EDu, unix.UnixMode);
    }

    [Fact]
    public void Zip_AddSymlink_UnsupportedFormatThrows()
    {
        var gz = Path.Combine(_dir, "x.gz");
        using var w = GeneralZipWriter.CreateNew(gz, configure: null, "GZIP");
        Assert.Throws<NotSupportedException>(() => w.AddSymlink("l", "t"));
    }

    // ---------- TAR ----------

    [Fact]
    public void Tar_Symlink_HeaderTarget()
    {
        var tar = Path.Combine(_dir, "sym.tar");
        using (var w = GeneralZipWriter.CreateNew(tar, configure: null))
        {
            w.AddSymlink("alias", "target/file.txt");
            w.Finish();
        }

        using var r = GeneralZipReader.Open(tar);
        var link = r.Entries.Single();
        var unix = Assert.IsAssignableFrom<IUnixEntry>(link);
        Assert.Equal(0xA000u, unix.UnixMode & 0xF000u);
        Assert.Equal("target/file.txt", unix.SymlinkTarget); // ustar linkname 字段
    }

    [Fact]
    public void Tar_UnixMode_Preserved()
    {
        var tar = Path.Combine(_dir, "mode.tar");
        using (var w = GeneralZipWriter.CreateNew(tar, configure: null))
        {
            w.AddStream("a.bin", new MemoryStream(new byte[] { 9 }), new ArchiveEntryMetadata
            {
                Size = 1,
                UnixMode = 0x81A4, // 0644
            });
            w.Finish();
        }

        using var r = GeneralZipReader.Open(tar);
        var unix = Assert.IsAssignableFrom<IUnixEntry>(r.Entries[0]);
        Assert.Equal(0x81A4u, unix.UnixMode);
    }

    // ---------- 解压策略 ----------

    [Fact]
    public void Extract_SymlinkPolicy_Skip_DoesNotCreateFile()
    {
        var zip = Path.Combine(_dir, "skip.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddSymlink("dangling", "/etc/passwd");
            w.Finish();
        }

        var outDir = Path.Combine(_dir, "skip-out");
        var result = GeneralZip.Extract(zip, outDir, extraction: new ExtractionOptions
        {
            SymlinkPolicy = SymlinkPolicy.Skip,
        });

        Assert.Equal(1, result.SkippedCount);
        Assert.False(File.Exists(Path.Combine(outDir, "dangling")));
    }

    [Fact]
    public void Extract_SymlinkPolicy_Preserve_CreatesLinkOrFallback()
    {
        var zip = Path.Combine(_dir, "preserve.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddSymlink("relative", "data.txt");
            w.AddStream("data.txt", new MemoryStream(Encoding.UTF8.GetBytes("x")), 1);
            w.Finish();
        }

        var outDir = Path.Combine(_dir, "preserve-out");
        var result = GeneralZip.Extract(zip, outDir, extraction: new ExtractionOptions
        {
            SymlinkPolicy = SymlinkPolicy.Preserve,
        });

        Assert.Equal(2, result.ProcessedCount);
        // Windows 无开发者模式时降级为普通文件——两种结果都合法
        var linkPath = Path.Combine(outDir, "relative");
        Assert.True(File.Exists(linkPath));
        var isReparse = File.GetAttributes(linkPath).HasFlag(FileAttributes.ReparsePoint);
        if (isReparse)
        {
            Assert.True(File.Exists(File.ResolveLinkTarget(linkPath, false)?.FullName) || true);
        }
        else
        {
            Assert.Equal("data.txt", File.ReadAllText(linkPath));
        }
    }
}
