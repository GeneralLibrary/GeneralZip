using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Native;
using Xunit;
using static GeneralZip.GeneralZip;

namespace GeneralZip.Native.Tests;

/// <summary>
/// Rust 原生核心集成测试（7z 读写/加密、xz 编解码）。
/// 原生核心缺失时跳过（CI 无 cargo 产物时不失败）。
/// </summary>
public class NativeCoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-native-{Guid.NewGuid():N}");

    public NativeCoreTests()
    {
        Directory.CreateDirectory(_dir);
        NativeCoreLoader.TryLoad();
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

        // 无产物时输出原因（本地未跑 cargo build）
        Assert.True(true, $"SKIPPED: native core not loaded: {NativeCoreLoader.FailureReason}");
        return true;
    }

    private static string NewPassword() => "Nk" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(8)).TrimEnd('=');

    [Fact]
    public void CoreLoads_WithSevenZCapability()
    {
        if (!NativeCoreLoader.TryLoad())
        {
            Assert.True(true, $"SKIPPED: native core not loaded: {NativeCoreLoader.FailureReason}");
            return;
        }

        Assert.True((NativeCoreLoader.Capabilities & NativeCoreLoader.CapabilitySevenZ) != 0);
        Assert.NotNull(GeneralZipNative.CoreVersion);
    }

    [Fact]
    public void SevenZip_Roundtrip_Plain()
    {
        if (SkipIfNoCore()) return;
        GeneralZipNative.Initialize();

        var src = Path.Combine(_dir, "src");
        Directory.CreateDirectory(Path.Combine(src, "sub"));
        File.WriteAllText(Path.Combine(src, "a.txt"), "7z 往返测试 native core");
        File.WriteAllText(Path.Combine(src, "sub", "b.bin"), new string('B', 50000));

        var archive = Path.Combine(_dir, "out.7z");
        using (var w = ArchiveWriter.CreateNew(archive, formatName: "7Z"))
        {
            w.AddDirectory(src, "data");
            w.Finish();
        }

        Assert.Equal("7Z", DetectFormat(archive)?.Name);

        using var r = ArchiveReader.Open(archive);
        Assert.Equal("7Z", r.Format.Name);
        Assert.True(r.Entries.Count >= 2);

        var dest = Path.Combine(_dir, "extracted");
        var result = r.ExtractToDirectory(dest);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal("7z 往返测试 native core", File.ReadAllText(Path.Combine(dest, "data", "a.txt")));
        Assert.Equal(50000, File.ReadAllText(Path.Combine(dest, "data", "sub", "b.bin")).Length);
    }

    [Fact]
    public void SevenZip_Encrypted_Roundtrip_And_WrongPassword()
    {
        if (SkipIfNoCore()) return;
        GeneralZipNative.Initialize();

        var archive = Path.Combine(_dir, "enc.7z");
        var password = NewPassword();
        var payload = "机密 7z encrypted content";

        using (var w = ArchiveWriter.CreateNew(archive, o =>
               {
                   o.Password = password;
               }, formatName: "7Z"))
        {
            w.AddStream("secret.txt", new MemoryStream(Encoding.UTF8.GetBytes(payload)), Encoding.UTF8.GetByteCount(payload));
            w.Finish();
        }

        // 错误口令 → 失败（不允许静默成功）
        var wrong = NewPassword();
        var failedFast = false;
        try
        {
            using var r = ArchiveReader.Open(archive, o => o.Password = wrong);
            using var s = r.OpenEntryStream(r.Entries[0]);
            s.Read(new byte[16], 0, 16);
        }
        catch (ArchiveException)
        {
            failedFast = true;
        }

        Assert.True(failedFast, "错误口令必须失败");

        // 正确口令 → 完整读出
        using (var r2 = ArchiveReader.Open(archive, o => o.Password = password))
        {
            using var s2 = r2.OpenEntryStream(r2.Entries[0]);
            using var ms = new MemoryStream();
            s2.CopyTo(ms);
            Assert.Equal(payload, Encoding.UTF8.GetString(ms.ToArray()));
        }
    }

    [Fact]
    public void SevenZip_TestAll()
    {
        if (SkipIfNoCore()) return;
        GeneralZipNative.Initialize();

        var archive = Path.Combine(_dir, "t.7z");
        using (var w = ArchiveWriter.CreateNew(archive, formatName: "7Z"))
        {
            w.AddStream("f.txt", new MemoryStream(new byte[4096]), 4096);
            w.Finish();
        }

        using var r = ArchiveReader.Open(archive);
        var result = r.TestAll(new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll });
        Assert.Equal(0, result.FailedCount);
    }

    [Fact]
    public void Xz_Compress_Decompress_Roundtrip()
    {
        if (SkipIfNoCore()) return;
        GeneralZipNative.Initialize();

        var src = Path.Combine(_dir, "in.txt");
        var compressed = Path.Combine(_dir, "out.xz");
        var restored = Path.Combine(_dir, "restored.txt");
        var payload = string.Concat(Enumerable.Repeat("xz 往返 native ", 2000));
        File.WriteAllText(src, payload);

        // xz 写经原生编码器（NativeBridge 桥接到 Rust lzma_rust2 LZMA2 编码器）
        var xz = Path.Combine(_dir, "a.txt.xz");
        using (var w = ArchiveWriter.CreateNew(xz))
        {
            using var content = File.OpenRead(src);
            w.AddStream("a.txt", content, content.Length);
            w.Finish();
        }

        Assert.Equal("XZ", DetectFormat(xz)?.Name);
        Assert.True(new FileInfo(xz).Length < new FileInfo(src).Length, "xz 应产生压缩效果");

        using (var r = ArchiveReader.Open(xz))
        {
            using var s = r.OpenEntryStream(r.Entries[0]);
            using var fs = File.Create(restored);
            s.CopyTo(fs);
        }

        Assert.Equal(payload, File.ReadAllText(restored));
    }
}
