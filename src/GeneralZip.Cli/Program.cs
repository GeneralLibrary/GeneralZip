using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Cryptography;

namespace GeneralZip.Cli;

/// <summary>
/// GeneralZip 命令行工具（dotnet tool，命令名 gz）。
/// 用法：gz &lt;command&gt; [args]，命令：a(压缩) x(解压) t(测试) l(列表) c(转换) rm(删除) i(信息) detect keygen
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            Console.OutputEncoding = Encoding.UTF8;
            if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
            {
                PrintHelp();
                return 0;
            }

            if (args[0] is "--version" or "version")
            {
                var coreVersion = global::GeneralZip.Native.GeneralZipNative.CoreVersion ?? "(absent)";
                var corePath = global::GeneralZip.Native.GeneralZipNative.CorePath ?? "-";
                var version = global::GeneralZip.GeneralZip.Version;
                Console.WriteLine($"gz (GeneralZip) {version}");
                Console.WriteLine($"native core: {coreVersion} @ {corePath}");
                return 0;
            }

            return args[0] switch
            {
                "a" or "add" => CmdAdd(args[1..]),
                "x" or "extract" => CmdExtract(args[1..]),
                "t" or "test" => CmdTest(args[1..]),
                "l" or "list" => CmdList(args[1..]),
                "c" or "convert" => CmdConvert(args[1..]),
                "rm" or "remove" => CmdRemove(args[1..]),
                "i" or "info" => CmdInfo(args[1..]),
                "detect" => CmdDetect(args[1..]),
                "keygen" => CmdKeygen(args[1..]),
                _ => Fail($"Unknown command: {args[0]} (try gz help)"),
            };
        }
        catch (Exception ex)
        {
            var original = Console.ForegroundColor;
            try
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"error: {ex.Message}");
            }
            finally
            {
                Console.ForegroundColor = original;
            }

            return 1;
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 2;
    }

    private static void PrintHelp()
    {
        var cliVersion = global::GeneralZip.GeneralZip.Version;
        Console.WriteLine($"""
            gz (GeneralZip) {cliVersion} — cross-format compression CLI

            Usage:
              gz a <archive> <path...> [-p <password>] [-e <algorithm>] [-m <method>] [--level <n>] [-P <pubkey>] [--volume <bytes>] [--parallel <n>]
              gz x <archive> <dir>  [-p <password>] [-g <glob>] [-G <exclude-glob>] [--parallel <n>] [--symlinks]
              gz t <archive>        [-p <password>] [--parallel <n>]
              gz l <archive>        [-p <password>]
              gz c <src-archive> <dst-archive> [-p <password>] [-w <write-password>] [-e <algorithm>]
              gz rm <archive> <entry...> | -g <glob>   [-p <password>]
              gz i <archive>        [-p <password>]
              gz detect <file>
              gz keygen             → SM2 key pair (private/public hex)

            Options:
              -p  password (or SM2 private key hex for SM2-GM archives)
              -e  encryption algorithm: WinZipAES256 (default) | SM4-GM | SM2-GM | ZipCrypto
              -m  zip method: Deflate | BZip2 | Zstd | Lzma
              -P  recipient SM2 public key hex (SM2-GM write)
              -g  include glob (x/rm), repeatable; -G exclude glob, repeatable

            Algorithms: WinZipAES128/256, SM4-GM (国密), SM2-GM envelope (国密信封), 7z AES-256, RAR (read), ZipCrypto (opt-in)
            Formats:    ZIP, 7z, RAR(read), TAR/GZ/BZ2, GZ, BZ2, XZ, ZSTD, LZ4, BROTLI, CPIO, ISO(read), CAB(read, stored)
            """);
    }

    private static (Dictionary<string, string> options, List<string> values) ParseArgs(string[] args)
    {
        var options = new Dictionary<string, string>();
        var values = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith('-') && arg.Length >= 2 && arg != "--")
            {
                var name = arg.TrimStart('-');
                var value = "true";
                if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                {
                    value = args[++i];
                }

                options[name] = value;
            }
            else
            {
                values.Add(arg);
            }
        }

        return (options, values);
    }

    private static void ApplyWriteOptions(string[] args, ArchiveWriteOptions o)
    {
        var (opts, _) = ParseArgs(args);
        if (opts.TryGetValue("p", out var password))
        {
            o.Password = password;
        }

        if (opts.TryGetValue("e", out var algorithm))
        {
            o.EncryptionAlgorithm = algorithm;
        }

        if (opts.TryGetValue("P", out var publicKey))
        {
            o.RecipientPublicKey = publicKey;
        }

        if (opts.TryGetValue("m", out var method))
        {
            o.ZipCompressionMethod = method switch
            {
                "Deflate" => ZipCompressionMethodChoice.Deflate,
                "BZip2" => ZipCompressionMethodChoice.BZip2,
                "Zstd" => ZipCompressionMethodChoice.Zstd,
                "Lzma" => ZipCompressionMethodChoice.Lzma,
                _ => throw new ArgumentException($"Unknown method: {method}"),
            };
        }

        if (opts.TryGetValue("level", out var level))
        {
            o.Level = level switch
            {
                "0" => CompressionLevelChoice.NoCompression,
                "1" => CompressionLevelChoice.Fastest,
                "3" => CompressionLevelChoice.SmallestSize,
                _ => CompressionLevelChoice.Optimal,
            };
        }

        if (opts.TryGetValue("volume", out var volume))
        {
            o.VolumeSize = long.Parse(volume);
        }

        if (opts.TryGetValue("parallel", out var parallel))
        {
            o.MaxDegreeOfParallelism = int.Parse(parallel);
        }
    }

    private static string RequirePassword(string[] args)
    {
        var (opts, _) = ParseArgs(args);
        return opts.TryGetValue("p", out var password) ? password : throw new ArgumentException("Password required (-p)");
    }

    // ---------- 命令 ----------

    private static int CmdAdd(string[] args)
    {
        var (opts, values) = ParseArgs(args);
        if (values.Count < 2)
        {
            return Fail("usage: gz a <archive> <path...>");
        }

        var archive = values[0];
        using var writer = GeneralZipWriter.CreateNew(archive, o => ApplyWriteOptions(args, o));

        writer.EntryProgress += (_, e) => PrintProgress(e.Entry.FullName, e.BytesProcessed, e.BytesTotal);
        writer.EntryCompleted += (_, e) => Console.WriteLine($"  added {e.Entry.FullName}");

        foreach (var source in values.Skip(1))
        {
            if (File.Exists(source))
            {
                writer.AddFile(source);
            }
            else if (Directory.Exists(source))
            {
                writer.AddDirectory(source);
            }
            else
            {
                return Fail($"path not found: {source}");
            }
        }

        writer.Finish();
        var fmt = writer.Format.Name;
        Console.WriteLine($"{archive}: {fmt} done");
        return 0;
    }

    private static long _lastPrint;

    private static void PrintProgress(string name, long bytes, long? total)
    {
        var now = Environment.TickCount64;
        if (now - _lastPrint < 100 && total.HasValue)
        {
            return; // 节流
        }

        _lastPrint = now;
        var pct = total.HasValue && total > 0 ? $"{100.0 * bytes / total:F0}%" : $"{bytes}B";
        Console.Write($"\r  {name} {pct}      ");
    }

    private static int CmdExtract(string[] args)
    {
        var (opts, values) = ParseArgs(args);
        if (values.Count < 2)
        {
            return Fail("usage: gz x <archive> <dir>");
        }

        var extraction = new ExtractionOptions();
        if (opts.TryGetValue("parallel", out var parallel))
        {
            extraction.MaxDegreeOfParallelism = int.Parse(parallel);
        }

        if (opts.TryGetValue("g", out var include))
        {
            extraction.IncludePatterns = ParseArgs(args).options.Where(kv => kv.Key == "g").Select(kv => kv.Value).ToList();
        }

        if (opts.TryGetValue("G", out var exclude))
        {
            extraction.ExcludePatterns = ParseArgs(args).options.Where(kv => kv.Key == "G").Select(kv => kv.Value).ToList();
        }

        if (opts.ContainsKey("symlinks"))
        {
            extraction.SymlinkPolicy = SymlinkPolicy.Preserve;
        }

        extraction.PreserveUnixAttributes = true;

        var preset = opts.TryGetValue("p", out var password) ? password : null;
        using var reader = GeneralZipReader.Open(values[0], preset != null
            ? (Action<ArchiveOpenOptions>)(o => o.Password = preset)
            : null);
        var result = reader.ExtractToDirectory(values[1], extraction);
        Console.WriteLine($"{values[0]}: {result.ProcessedCount} extracted, {result.SkippedCount} skipped, {result.Failures.Count} failed");
        return result.Failures.Count == 0 ? 0 : 1;
    }

    private static int CmdTest(string[] args)
    {
        var (opts, values) = ParseArgs(args);
        if (values.Count < 1)
        {
            return Fail("usage: gz t <archive>");
        }

        var extraction = new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll };
        if (opts.TryGetValue("parallel", out var parallel))
        {
            extraction.MaxDegreeOfParallelism = int.Parse(parallel);
        }

        using var reader = GeneralZipReader.Open(values[0], o =>
        {
            if (opts.TryGetValue("p", out var password))
            {
                o.Password = password;
            }
        });
        var result = reader.TestAll(extraction);
        Console.WriteLine(result.Success
            ? $"{values[0]}: OK ({result.ProcessedCount} entries)"
            : $"{values[0]}: {result.Failures.Count} FAILED");
        foreach (var failure in result.Failures)
        {
            Console.WriteLine($"  {failure.EntryName}: {failure.Exception.Message}");
        }

        return result.Success ? 0 : 1;
    }

    private static int CmdList(string[] args)
    {
        var (opts, values) = ParseArgs(args);
        if (values.Count < 1)
        {
            return Fail("usage: gz l <archive>");
        }

        using var reader = GeneralZipReader.Open(values[0], o =>
        {
            if (opts.TryGetValue("p", out var password))
            {
                o.Password = password;
            }
        });

        Console.WriteLine($"format={reader.Format.Name} entries={reader.Entries.Count} encrypted={reader.IsEncrypted}");
        foreach (var entry in reader.Entries)
        {
            var size = entry.Size >= 0 ? entry.Size.ToString() : "-";
            var comp = entry.CompressedSize >= 0 ? entry.CompressedSize.ToString() : "-";
            var enc = entry.IsEncrypted ? $" [{entry.EncryptionAlgorithm}]" : string.Empty;
            var time = entry.LastWriteTime?.ToString("yyyy-MM-dd HH:mm") ?? "-";
            var mode = entry is IUnixEntry { UnixMode: { } m }
                ? " mode=" + Convert.ToString(m & 0xFFF, 8).PadLeft(4, '0')
                : string.Empty;
            Console.WriteLine($"{(entry.IsDirectory ? "d" : "-")} {time} {size,12} {comp,12}{enc}{mode}  {entry.FullName}");
        }

        return 0;
    }

    private static int CmdConvert(string[] args)
    {
        var (opts, values) = ParseArgs(args);
        if (values.Count < 2)
        {
            return Fail("usage: gz c <src-archive> <dst-archive>");
        }

        global::GeneralZip.GeneralZip.Convert(values[0], values[1], o =>
        {
            if (opts.TryGetValue("w", out var writePassword))
            {
                o.Password = writePassword;
            }

            if (opts.TryGetValue("e", out var algorithm))
            {
                o.EncryptionAlgorithm = algorithm;
            }
        }, o =>
        {
            if (opts.TryGetValue("p", out var password))
            {
                o.Password = password;
            }
        });

        Console.WriteLine($"{values[0]} → {values[1]}");
        return 0;
    }

    private static int CmdRemove(string[] args)
    {
        var (opts, values) = ParseArgs(args);
        if (values.Count < 1)
        {
            return Fail("usage: gz rm <archive> <entry...> | -g <glob>");
        }

        var globs = opts.Where(kv => kv.Key == "g").Select(kv => kv.Value).ToList();
        global::GeneralZip.GeneralZip.Remove(values[0],
            entryNames: values.Skip(1),
            predicate: globs.Count > 0
                ? (Func<IArchiveEntry, bool>)(e => globs.Any(g => GlobMatcher.IsMatch(e.FullName, g)))
                : null);

        Console.WriteLine($"{values[0]} updated");
        return 0;
    }

    private static int CmdInfo(string[] args)
    {
        var (opts, values) = ParseArgs(args);
        if (values.Count < 1)
        {
            return Fail("usage: gz i <archive>");
        }

        var info = global::GeneralZip.GeneralZip.DetectFormat(values[0]);
        Console.WriteLine($"format:   {info?.Name ?? "unknown"}");
        if (info != null)
        {
            Console.WriteLine($"details:  {info.Description}");
        }

        using var reader = GeneralZipReader.Open(values[0], o =>
        {
            if (opts.TryGetValue("p", out var password))
            {
                o.Password = password;
            }
        });

        var files = reader.Entries.Count(e => !e.IsDirectory);
        var dirs = reader.Entries.Count - files;
        var totalSize = reader.Entries.Sum(e => Math.Max(0, e.Size));
        var totalComp = reader.Entries.Sum(e => Math.Max(0, e.CompressedSize));
        Console.WriteLine($"entries:  {files} files, {dirs} dirs");
        Console.WriteLine($"size:     {totalSize} → {totalComp}");
        Console.WriteLine($"encrypted: {(reader.IsEncrypted ? "yes" : "no")}");
        var nativeVersion = global::GeneralZip.Native.GeneralZipNative.CoreVersion ?? "(absent)";
        Console.WriteLine($"native:   {nativeVersion}");
        return 0;
    }

    private static int CmdDetect(string[] args)
    {
        if (args.Length < 1)
        {
            return Fail("usage: gz detect <file>");
        }

        var info = global::GeneralZip.GeneralZip.DetectFormat(args[0]);
        if (info == null)
        {
            Console.WriteLine("unknown");
            return 1;
        }

        Console.WriteLine($"{info.Name} — {info.Description}");
        return 0;
    }

    private static int CmdKeygen(string[] args)
    {
        var keyPair = Sm2KeyPair.Generate();
        Console.WriteLine($"private (hex): {keyPair.PrivateKeyHex}");
        Console.WriteLine($"public  (hex): {keyPair.PublicKeyHex}");
        Console.WriteLine("Keep the private key safe; the public key is the SM2-GM recipient key (-P).");
        return 0;
    }
}
