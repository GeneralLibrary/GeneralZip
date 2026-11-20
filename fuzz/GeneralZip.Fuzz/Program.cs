using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Fuzz;

/// <summary>读路径 AFL fuzz 入口；传入文件路径时可重放 corpus 样本。</summary>
internal static class Program
{
    private static void Main(string[] args)
    {
        if (args.Length != 0)
        {
            foreach (var path in args)
            {
                var files = Directory.Exists(path)
                    ? Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
                    : new[] { path };
                foreach (var file in files)
                {
                    FuzzReadPath(File.ReadAllBytes(file));
                }
            }

            return;
        }

        SharpFuzz.Fuzzer.RunOnce(stream =>
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            FuzzReadPath(ms.ToArray());
        });
    }

    /// <summary>fuzz 目标：整段输入走 OpenRead → 全条目流式读取。</summary>
    public static void FuzzReadPath(byte[] input)
    {
        try
        {
            using var stream = new MemoryStream(input, writable: false);
            using var reader = GeneralZipReader.Open(stream);
            foreach (var entry in reader.Entries)
            {
                using var content = reader.OpenEntryStream(entry);
                content.CopyTo(Stream.Null);
            }
        }
        catch (Exception ex) when (
            ex is ArchiveException
            or IOException
            or NotSupportedException
            or ArgumentException
            or InvalidOperationException
            or System.Security.Cryptography.CryptographicException
            or System.IO.InvalidDataException)
        {
            // 预期内的拒识：格式/结构/口令/损坏 → 不是 fuzz 发现
        }
    }
}
