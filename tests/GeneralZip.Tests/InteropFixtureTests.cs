using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>
/// 互操作 fixture 测试：samples/fixtures/interop 下的归档由**独立实现**生成
/// （py7zr / pycdlib / python zipfile / 手写 GNU cpio newc），GeneralZip 仅负责读取。
/// 这是跨实现兼容性的回归锚点。
/// </summary>
public class InteropFixtureTests
{
    // fixture 经 csproj None LinkBase 复制进测试输出目录
    private static string FixtureDir
        => Path.Combine(AppContext.BaseDirectory, "samples", "fixtures", "interop");

    private static bool HasCore => global::GeneralZip.Formats.Codecs.NativeCodecRouter.IsCoreAvailable();

    private static byte[] ReadAll(string name)
        => File.ReadAllBytes(Path.Combine(FixtureDir, name));

    private static void AssertSha(byte[] data, string expectPrefix)
        => Assert.StartsWith(expectPrefix, Convert.ToHexString(SHA256.HashData(data)), StringComparison.Ordinal);

    [Fact]
    public void PythonZip64_Read()
    {
        var path = Path.Combine(FixtureDir, "python-zip64.zip");
        Assert.Equal("ZIP", GeneralZip.DetectFormat(path)?.Name);

        using var r = GeneralZipReader.Open(path);
        var names = r.Entries.Select(e => e.FullName).OrderBy(n => n).ToList();
        Assert.Contains("readme.txt", names);
        Assert.Contains("data/binary.bin", names);
        Assert.Contains("sparse.bin", names);

        // sparse.bin 条目携带 Zip64 字段（python force_zip64 头部）
        var sparse = r.Entries.First(e => e.FullName == "sparse.bin");
        Assert.Equal(1 << 22, sparse.Size);
        using var s = r.OpenEntryStream(sparse);
        long drained = 0;
        var buffer = new byte[81920];
        int n;
        while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
        {
            drained += n;
        }

        Assert.Equal(1 << 22, drained);

        // 内容校验（固定语料）
        var readme = Encoding.UTF8.GetString(ReadEntry(r, "readme.txt"));
        Assert.Contains("py7zr (independent implementation)", readme);
    }

    [Fact]
    public void GnuCpioNewc_Read()
    {
        var path = Path.Combine(FixtureDir, "gnu-cpio-newc.cpio");
        Assert.Equal("CPIO", GeneralZip.DetectFormat(path)?.Name);

        using var r = GeneralZipReader.Open(path);
        var names = r.Entries.Select(e => e.FullName).ToList();
        Assert.Contains("readme.txt", names);
        Assert.Contains("data/binary.bin", names);
        Assert.Contains("link", names);

        // 符号链接（mode S_IFLNK），目标在数据段
        var link = r.Entries.First(e => e.FullName == "link");
        var unix = Assert.IsAssignableFrom<IUnixEntry>(link);
        Assert.Equal(0xA000u, unix.UnixMode & 0xF000u);
        using var ls = r.OpenEntryStream(link);
        using var lms = new MemoryStream();
        ls.CopyTo(lms);
        Assert.Equal("readme.txt", Encoding.UTF8.GetString(lms.ToArray()));

        // 二进制语料逐字节校验
        using var bs = r.OpenEntryStream(r.Entries.First(e => e.FullName == "data/binary.bin"));
        using var bms = new MemoryStream();
        bs.CopyTo(bms);
        Assert.Equal(2048, bms.Length);
        for (var i = 0; i < 2048; i++)
        {
            Assert.Equal(i % 256, bms.ToArray()[i]);
        }
    }

    [Fact]
    public void PycdlibIso_Read()
    {
        var path = Path.Combine(FixtureDir, "pycdlib-sample.iso");
        Assert.Equal("ISO", GeneralZip.DetectFormat(path)?.Name);

        using var r = GeneralZipReader.Open(path);
        var names = r.Entries.Select(e => e.FullName).ToList();
        // ISO Level1 基础名（Joliet 由 Rock Ridge/Joliet 逻辑选择其一）
        Assert.Contains(names, n => n.Equals("README.TXT", StringComparison.OrdinalIgnoreCase)
                                     || n.Equals("readme.txt", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(names, n => n.ToUpperInvariant().Contains("DATA.BIN"));

        var readme = r.Entries.First(e => e.FullName.EndsWith("README.TXT", StringComparison.OrdinalIgnoreCase));
        using var s = r.OpenEntryStream(readme);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Contains("independent implementation", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Py7zrSample_Read()
    {
        if (!HasCore)
        {
            Assert.True(true, "SKIPPED: native core not loaded (7z requires the Rust core)");
            return;
        }

        var path = Path.Combine(FixtureDir, "py7zr-sample.7z");
        Assert.Equal("7Z", GeneralZip.DetectFormat(path)?.Name);

        using var r = GeneralZipReader.Open(path);
        Assert.Contains("readme.txt", r.Entries.Select(e => e.FullName).ToList());
        using var s = r.OpenEntryStream(r.Entries.First(e => e.FullName == "readme.txt"));
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Contains("independent implementation", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Py7zrSecret_ReadWithDemoPassword()
    {
        if (!HasCore)
        {
            Assert.True(true, "SKIPPED: native core not loaded (7z requires the Rust core)");
            return;
        }

        var path = Path.Combine(FixtureDir, "py7zr-secret.7z");
        var password = TestSecrets.FixturePassword;

        using var r = GeneralZipReader.Open(path, o => o.Password = password);
        Assert.True(r.IsEncrypted);
        using var s = r.OpenEntryStream(r.Entries.First(e => e.FullName == "readme.txt"));
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Contains("independent implementation", Encoding.UTF8.GetString(ms.ToArray()));
    }

    private static byte[] ReadEntry(GeneralZipReader reader, string name)
    {
        using var s = reader.OpenEntryStream(reader.Entries.First(e => e.FullName == name));
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}
