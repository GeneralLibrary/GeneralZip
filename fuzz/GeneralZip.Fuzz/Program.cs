using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Fuzz;

/// <summary>
/// 读路径 fuzz 入口（SharpFuzz/libFuzzer）。
/// 运行方式：
///   dotnet publish fuzz/GeneralZip.Fuzz -c Release -f net8.0 -o fuzz/out
///   sharpfuzz fuzz/out/GeneralZip.dll
///   ./fuzz/out/GeneralZip.Fuzz corpus/
/// 断言面：任何输入都只允许归档类异常；崩溃即 fuzz 发现（详见 fuzz/README.md）。
/// </summary>
internal static class Program
{
    /// <summary>libFuzzer 入口（输入为流）。</summary>
    private static void Main()
    {
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
