using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Native;
using static GeneralZip.GeneralZip;

// =====================================================================
// GeneralZip 全格式压缩/解压性能基准
// 用法: dotnet run -c Release [-- <每个profile大小MB> <预热次数> <测量次数>]
// 说明: 自研 Stopwatch 计时（不引入基准测试框架依赖），取多次测量的最优值。
// =====================================================================

var sizeMb = args.Length > 0 && int.TryParse(args[0], out var mb) ? mb : 8;
var warmups = args.Length > 1 && int.TryParse(args[1], out var w) ? w : 1;
var runs = args.Length > 2 && int.TryParse(args[2], out var r) ? r : 3;

var nativeOk = GeneralZipNative.Initialize();
Initialize();

Console.WriteLine($"GeneralZip benchmark  native={(nativeOk ? "available" : "missing (skips 7z/BZ2/XZ/ZSTD/LZ4)")}");
Console.WriteLine($"Runtime: {Environment.Version}  OS: {Environment.OSVersion.VersionString}  Logical cores: {Environment.ProcessorCount}");
Console.WriteLine($"Data spec: {sizeMb} MB per profile x 3 | {warmups} warmup(s) | {runs} run(s) (best of)");
Console.WriteLine();

// ---------- 测试数据（确定性生成，三类典型负载） ----------
var textProfile = BuildTextData(sizeMb);
var binaryProfile = BuildRandomData(sizeMb);
var mixedProfile = BuildMixedData(sizeMb);

var profiles = new (string Name, byte[] Data)[]
{
    ("text (highly compressible)", textProfile),
    ("mixed (medium)", mixedProfile),
    ("random (incompressible)", binaryProfile),
};

// ---------- 基准项定义 ----------
var items = new List<BenchItem>
{
    new("ZIP-Store",                ".zip", o => o.Level = CompressionLevelChoice.NoCompression, native: false),
    new("ZIP-Deflate",              ".zip", o => o.Level = CompressionLevelChoice.Optimal, native: false),
    new("ZIP-Deflate+ZipCrypto",    ".zip", o => { o.EncryptionAlgorithm = "ZipCrypto"; o.Password = Pw(); o.AllowWeakZipCrypto = true; }, native: false),
    new("ZIP-Deflate+WinZipAES128", ".zip", o => { o.EncryptionAlgorithm = "WinZipAES128"; o.Password = Pw(); }, native: false),
    new("ZIP-Deflate+WinZipAES256", ".zip", o => { o.EncryptionAlgorithm = "WinZipAES256"; o.Password = Pw(); }, native: false),
    new("ZIP-Deflate+SM4-GM",       ".zip", o => { o.EncryptionAlgorithm = "SM4-GM"; o.Password = Pw(); }, native: false),
    new("TAR",                      ".tar", null, native: false),
    new("GZ",                       ".gz", null, native: false),
    new("TAR.GZ",                   ".tar.gz", null, native: false),
    new("7Z-LZMA2",                 ".7z", null, native: true),
    new("7Z-LZMA2+AES256",          ".7z", o => o.Password = Pw(), native: true),
    new("BZ2",                      ".bz2", null, native: true),
    new("XZ",                       ".xz", null, native: true),
    new("ZSTD",                     ".zst", null, native: true),
    new("LZ4",                      ".lz4", null, native: true),
};

var workDir = Path.Combine(Path.GetTempPath(), "gzp-bench");
if (Directory.Exists(workDir)) Directory.Delete(workDir, true);
Directory.CreateDirectory(workDir);

// ---------- 执行 ----------
var results = new List<BenchResult>();
var sequence = 0;

foreach (var profile in profiles)
{
    Console.WriteLine($"=== data: {profile.Name} ({profile.Data.Length / 1024.0 / 1024:F1} MB) ===");
    Console.WriteLine($"{"format@data",-34} {"compress MB/s",13} {"extract MB/s",13} {"ratio",8}  {"output",10}");
    Console.WriteLine(new string('-', 82));

    foreach (var item in items)
    {
        if (item.NeedsNative && !nativeOk)
        {
            Console.WriteLine($"{item.Label + "@" + profile.Name,-34} {"(skipped: no native core)",22}");
            continue;
        }

        try
        {
            var result = BenchOne(item, profile.Data, workDir, warmups, runs, profile.Name, () => ++sequence);
            results.Add(result);
            Console.WriteLine($"{result.Label,-34} {result.CompressMbps,10:F1} {result.DecompressMbps,10:F1} {result.Ratio,8:P1}  {FormatSize(result.ArchiveSize),10}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{item.Label + "@" + profile.Name,-34} FAILED: {ex.Message}");
        }
    }

    Console.WriteLine();
}

// 汇总（以混合数据为主视图）
Console.WriteLine("=== summary (mixed data) ===");
Console.WriteLine($"{"format",-34} {"compress MB/s",13} {"extract MB/s",13} {"ratio",8}");
foreach (var row in results.Where(x => x.Profile == "mixed (medium)"))
{
    Console.WriteLine($"{row.Label,-34} {row.CompressMbps,10:F1} {row.DecompressMbps,10:F1} {row.Ratio,8:P1}");
}

try { Directory.Delete(workDir, true); } catch { }

static string Pw() => "Bench" + "-Password-" + "2026";

// ---------- 实现 ----------

static BenchResult BenchOne(BenchItem item, byte[] data, string workDir, int warmups, int runs, string profileName, Func<int> nextSeq)
{
    var mbytes = data.Length / 1024.0 / 1024.0;
    long archiveSize = 0;

    // 每次写/读使用独立文件名：规避句柄释放时序造成的共享冲突，且便于清理
    string NewFile() => Path.Combine(workDir, $"{nextSeq():D4}{item.Extension}");

    for (var i = 0; i < warmups; i++)
    {
        var f = NewFile();
        WriteArchive(item, f, data);
        ReadArchive(f, item);
        TryDelete(f);
    }

    var bestCompress = double.MaxValue;
    for (var i = 0; i < runs; i++)
    {
        var f = NewFile();
        var sw = Stopwatch.StartNew();
        WriteArchive(item, f, data);
        sw.Stop();
        archiveSize = new FileInfo(f).Length;
        bestCompress = Math.Min(bestCompress, sw.Elapsed.TotalSeconds);
        TryDelete(f);
    }

    var bestDecompress = double.MaxValue;
    for (var i = 0; i < runs; i++)
    {
        var f = NewFile();
        WriteArchive(item, f, data); // 保持与压缩测量一致的产物
        var sw = Stopwatch.StartNew();
        ReadArchive(f, item);
        sw.Stop();
        TryDelete(f);
        bestDecompress = Math.Min(bestDecompress, sw.Elapsed.TotalSeconds);
    }

    return new BenchResult(item.Label, mbytes / bestCompress, mbytes / bestDecompress,
        (double)archiveSize / data.Length, archiveSize, profileName);
}

static void TryDelete(string file)
{
    try { File.Delete(file); } catch { /* 偶发句柄延迟由唯一文件名兜底 */ }
}

static void WriteArchive(BenchItem item, string file, byte[] data)
{
    using var writer = GeneralZipWriter.CreateNew(file, item.Configure, formatName: item.FormatName);
    writer.AddStream("data.bin", new MemoryStream(data), data.Length);
    writer.Finish();
}

static long ReadArchive(string file, BenchItem item)
{
    using var reader = GeneralZipReader.Open(file, o => o.Password = Pw());
    long total = 0;
    foreach (var entry in reader.Entries)
    {
        if (entry.IsDirectory) continue;
        using var stream = reader.OpenEntryStream(entry);
        var buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
        }
    }

    if (total <= 0)
    {
        throw new InvalidDataException($"{file}: extracted 0 bytes");
    }

    return total;
}

static byte[] BuildTextData(int sizeMb)
{
    // 高可压：重复的中文/英文混合日志样式文本
    var line = "2026-10-29 INFO [GeneralZip] compression benchmark Lorem ipsum dolor sit amet 0123456789\r\n";
    var block = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat(line, 64)));
    var target = sizeMb * 1024 * 1024;
    var data = new byte[target];
    var pos = 0;
    while (pos < target)
    {
        var n = Math.Min(block.Length, target - pos);
        Buffer.BlockCopy(block, 0, data, pos, n);
        pos += n;
    }

    return data;
}

static byte[] BuildRandomData(int sizeMb)
{
    var data = new byte[sizeMb * 1024 * 1024];
    RandomNumberGenerator.Fill(data);
    return data;
}

static byte[] BuildMixedData(int sizeMb)
{
    var half = sizeMb * 1024 * 1024 / 2;
    var text = BuildTextData(sizeMb);
    var random = BuildRandomData(sizeMb);
    var data = new byte[sizeMb * 1024 * 1024];
    Buffer.BlockCopy(text, 0, data, 0, half);
    Buffer.BlockCopy(random, 0, data, half, half);
    return data;
}

static string FormatSize(long bytes) => bytes switch
{
    >= 1 << 20 => $"{bytes / 1024.0 / 1024:F1} MB",
    >= 1 << 10 => $"{bytes / 1024.0:F1} KB",
    _ => $"{bytes} B",
};

internal sealed record BenchResult(string Label, double CompressMbps, double DecompressMbps, double Ratio, long ArchiveSize, string Profile);

internal sealed class BenchItem
{
    public BenchItem(string label, string extension, Action<ArchiveWriteOptions>? configure, bool native)
    {
        Label = label;
        Extension = extension;
        Configure = configure;
        NeedsNative = native;
    }

    public string Label { get; }

    public string Extension { get; }

    public Action<ArchiveWriteOptions>? Configure { get; }

    public bool NeedsNative { get; }

    /// <summary>由扩展名推断显式格式名（.tar.gz 等复合扩展名由后缀匹配解析）。</summary>
    public string FormatName => GeneralZip.GeneralZip.Registry.DetectByExtension("x" + Extension)?.Info.Name ?? "ZIP";
}
