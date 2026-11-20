using System;
using System.IO;
using System.Security.Cryptography;
using GeneralZip;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>
/// 读路径健壮性测试：任意/变异字节流入读取器，只允许归档类异常
/// （ArchiveException 家族/IOException/NotSupportedException），绝不允许进程级崩溃
/// （AccessViolation、越界、StackOverflow 等）。fuzz/GeneralZip.Fuzz 提供持续 fuzz 入口。
/// </summary>
public class RobustnessTests
{
    private static void AssertSafe(Exception ex)
    {
        Assert.True(
            ex is ArchiveException or IOException or NotSupportedException or ArgumentException or InvalidOperationException
                or System.Security.Cryptography.CryptographicException or ArgumentOutOfRangeException or System.IO.InvalidDataException,
            $"unexpected exception type from malformed input: {ex.GetType().Name}: {ex.Message}");
    }

    [Fact]
    public void RandomBytes_NeverCrash()
    {
        var rng = RandomNumberGenerator.Create();
        var buffer = new byte[4096];
        for (var round = 0; round < 200; round++)
        {
            rng.GetBytes(buffer);
            try
            {
                using var stream = new MemoryStream(buffer, writable: false);
                using var reader = GeneralZipReader.Open(stream);
                foreach (var entry in reader.Entries)
                {
                    using var s = reader.OpenEntryStream(entry);
                    s.CopyTo(Stream.Null);
                }
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
            {
                AssertSafe(ex);
            }
        }
    }

    [Fact]
    public void TruncatedArchive_NeverCrash()
    {
        // 生成真实 ZIP，然后逐级截断
        var payload = new byte[100_000];
        RandomNumberGenerator.Fill(payload);
        using var baseStream = new MemoryStream();
        using (var w = GeneralZipWriter.CreateNew(baseStream, "ZIP"))
        {
            w.AddStream("a.bin", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        var full = baseStream.ToArray();
        for (var cut = 0; cut < full.Length; cut += Math.Max(1, full.Length / 200))
        {
            try
            {
                using var stream = new MemoryStream(full, 0, cut, writable: false);
                using var reader = GeneralZipReader.Open(stream);
                foreach (var entry in reader.Entries)
                {
                    using var s = reader.OpenEntryStream(entry);
                    s.CopyTo(Stream.Null);
                }
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
            {
                AssertSafe(ex);
            }
        }
    }

    [Fact]
    public void BitFlips_NeverCrash()
    {
        var payload = new byte[50_000];
        RandomNumberGenerator.Fill(payload);
        using var baseStream = new MemoryStream();
        using (var w = GeneralZipWriter.CreateNew(baseStream, "ZIP"))
        {
            w.AddStream("a.bin", new MemoryStream(payload), payload.Length);
            w.Finish();
        }

        var full = baseStream.ToArray();
        for (var round = 0; round < 300; round++)
        {
            var mutated = (byte[])full.Clone();
            for (var flip = 0; flip < 4; flip++)
            {
                // 变异位置为测试数据选择（非密钥材料），用 CSPRNG GetInt32 保持来源一致
                var pos = RandomNumberGenerator.GetInt32(mutated.Length);
                mutated[pos] ^= (byte)(1 << RandomNumberGenerator.GetInt32(8));
            }

            try
            {
                using var stream = new MemoryStream(mutated, writable: false);
                using var reader = GeneralZipReader.Open(stream);
                foreach (var entry in reader.Entries)
                {
                    using var s = reader.OpenEntryStream(entry);
                    s.CopyTo(Stream.Null);
                }
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
            {
                AssertSafe(ex);
            }
        }
    }
}
