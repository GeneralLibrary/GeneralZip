using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Native;
using static GeneralZip.GeneralZip;   // 启动引导类与组件同名：using static 后裸调用一行式 API

// 演示用口令：运行时拼接派生（避免源码硬编码；实际应用请从密钥管理服务/用户输入获取）
static string DemoPassword(string label) => "GZ-" + label + "-Demo";

// ===== 0) 启动引导：核心注册表 + 可选原生核心 =====
Initialize();                          // 幂等：确保内置格式/加密算法注册
if (GeneralZipNative.Initialize())     // 可选：Rust 原生核心（7z/xz 能力；缺失时优雅降级）
{
    Console.WriteLine($"[native core] v{GeneralZipNative.CoreVersion} loaded (7z/xz available)");
}
else
{
    Console.WriteLine("[native core] not loaded: 7z/RAR unavailable; pure-managed capabilities unaffected");
}

var work = Path.Combine(Path.GetTempPath(), "gzp-sample");
if (Directory.Exists(work)) Directory.Delete(work, true);
Directory.CreateDirectory(work);

// ===== 1) 一行式：压缩目录到 ZIP =====
var src = Path.Combine(work, "Data");
Directory.CreateDirectory(src);
await File.WriteAllTextAsync(Path.Combine(src, "readme.txt"), "GeneralZip sample file");
await File.WriteAllTextAsync(Path.Combine(src, "data.csv"), "id,name\n1,Alice\n2,Bob");

var zip = Path.Combine(work, "backup.zip");
await CompressAsync(src, zip, o => o.Level = CompressionLevelChoice.Optimal);
Console.WriteLine($"[one-liner] compressed: {zip} ({new FileInfo(zip).Length}B, format {DetectFormat(zip)?.Name})");

// ===== 1.5) 启动引导说明 =====
// GeneralZip.Initialize() 为幂等引导入口（确保内置格式/算法注册），放在程序启动处调用一次即可。
// 原生能力（7z/RAR/xz 写）另需引用 GeneralZip.Native 并调用 GeneralZipNative.Initialize()。

// ===== 2) 国密 SM4 加密 ZIP（加密写 → 解密读） =====
var sm4Zip = Path.Combine(work, "secret-sm4.zip");
var sm4Password = DemoPassword("SM4");

await CompressAsync(src, sm4Zip, o =>
{
    o.EncryptionAlgorithm = "SM4-GM";       // 国密：SM4-CTR + SM3-HMAC（见 docs/CRYPTO-SPEC.md）
    o.Password = sm4Password;
    o.KdfIterations = 10_000;               // SM3-PBKDF2 迭代次数
});

using (var reader = await ArchiveReader.OpenAsync(sm4Zip, o => o.Password = sm4Password))
{
    Console.WriteLine($"[SM4] SM4-GM archive: {reader.Entries.Count} entries, algorithm {reader.Entries[0].EncryptionAlgorithm}");
    var extractDir = Path.Combine(work, "sm4-out");
    var result = reader.ExtractToDirectory(extractDir);
    Console.WriteLine($"[SM4] extracted {result.ProcessedCount} files, {result.FailedCount} failed");
}

// ===== 3) 事件驱动：进度 + 密码协商 =====
var aesZip = Path.Combine(work, "event-demo.zip");
var aesPassword = DemoPassword("AES");
using (var writer = ArchiveWriter.CreateNew(aesZip, o =>
{
    o.EncryptionAlgorithm = "WinZipAES256"; // 主流通用方案（WinZip/7-Zip/Windows 可读）
    o.Password = aesPassword;
    o.Progress = new Progress<ArchiveProgress>(p =>
        Console.Write($"\r[progress] {p.Percent:F0}% {p.CurrentEntry}          "));
}))
{
    for (var i = 0; i < 50; i++)
    {
        var bytes = new byte[100_000];
        Random.Shared.NextBytes(bytes);
        writer.AddStream($"blob-{i:D2}.bin", new MemoryStream(bytes), bytes.Length);
    }

    await writer.FinishAsync();
}

Console.WriteLine();

using (var reader = ArchiveReader.Open(aesZip, null, r =>
       {
           // 整包加密格式请在 initialize 钩子中订阅（ZIP 分条目加密也可打开后订阅）
           r.PasswordRequired += (_, e) =>
           {
               Console.WriteLine($"[event] password required (attempt {e.Attempt}): {e.EntryName}");
               e.Password = aesPassword;
           };
       }))
{
    var progressLines = 0;
    reader.OverallProgress += (_, p) =>
    {
        if (++progressLines % 10 == 0)
        {
            Console.WriteLine($"[event] overall {p.Percent:F0}% ({p.EntriesCompleted}/{p.EntriesTotal}, {p.BytesPerSecond / 1024:F0} KB/s)");
        }
    };

    var extractDir = Path.Combine(work, "event-out");
    var result = await reader.ExtractToDirectoryAsync(extractDir);
    Console.WriteLine($"[event] extraction done: ok {result.ProcessedCount}, skipped {result.SkippedCount}, failed {result.FailedCount}");
}

// ===== 4) 原生格式：7z（加密读写）与 xz =====
if (NativeCoreLoader.IsAvailable)
{
    var sevenZip = Path.Combine(work, "arch.7z");
    var sevenZPassword = DemoPassword("7Z");
    using (var w = ArchiveWriter.CreateNew(sevenZip, o =>
           {
               o.Password = sevenZPassword;     // 7z 标准 AES-256（Rust 核心：sevenz-rust2）
           }, formatName: "7Z"))
    {
        await w.AddDirectoryAsync(src);
        await w.FinishAsync();
    }

    using (var r = ArchiveReader.Open(sevenZip, o => o.Password = sevenZPassword))
    {
        var result = await r.ExtractToDirectoryAsync(Path.Combine(work, "7z-out"));
        Console.WriteLine($"[7z] extracted {result.ProcessedCount} entries (LZMA2 + AES-256)");
    }

    // xz 单文件编解码（Rust 核心 LZMA2 编码 + 容器）
    var bigFile = Path.Combine(work, "big.log");
    await File.WriteAllTextAsync(bigFile, string.Concat(Enumerable.Repeat("log line lorem ipsum ", 5000)));
    var xzFile = bigFile + ".xz";
    using (var w = ArchiveWriter.CreateNew(xzFile))
    {
        using var content = File.OpenRead(bigFile);
        w.AddStream("big.log", content, content.Length);
        w.Finish();
    }

    Console.WriteLine($"[xz] {new FileInfo(bigFile).Length}B → {new FileInfo(xzFile).Length}B");
}
else
{
    Console.WriteLine("[7z/xz] skipped (native core not deployed; see README build guide)");
}

// ===== 5) 完整性测试 =====
var testResult = Test(zip);
Console.WriteLine($"[test] {zip} integrity: {(testResult.Success ? "passed" : $"failed {testResult.FailedCount}")}");

Console.WriteLine("\nSamples finished. See docs/ARCHITECTURE.md for more APIs.");
