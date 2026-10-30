using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>事件链路测试：进度 / 口令协商 / 覆盖询问 / 错误策略 / 取消。</summary>
public class EventTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-event-{Guid.NewGuid():N}");

    public EventTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void EntryLifecycle_Events_Fire()
    {
        var zip = Path.Combine(_dir, "life.zip");
        var started = new List<string>();
        var completed = new List<string>();
        var overall = new List<ArchiveProgress>();

        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("one.txt", new MemoryStream(new byte[100_000]), 100_000);
            w.AddStream("two.txt", new MemoryStream(new byte[50]), 50);
            w.Finish();
        }

        using (var r = GeneralZipReader.Open(zip))
        {
            r.EntryStarted += (_, e) => started.Add(e.EntryName);
            r.EntryCompleted += (_, e) => completed.Add(e.EntryName);
            r.OverallProgress += (_, p) => overall.Add(p);
            r.ExtractToDirectory(Path.Combine(_dir, "out"));
        }

        Assert.Equal(new[] { "one.txt", "two.txt" }, started);
        Assert.Equal(new[] { "one.txt", "two.txt" }, completed);
        Assert.NotEmpty(overall);
        Assert.Equal(100, Math.Floor(overall.Last().Percent ?? 0));
    }

    [Fact]
    public void WriteProgress_Fires()
    {
        var zip = Path.Combine(_dir, "wprog.zip");
        var percents = new List<double?>();

        using (var w = GeneralZipWriter.CreateNew(zip, o => o.Progress = new Progress<ArchiveProgress>(p => percents.Add(p.Percent))))
        {
            w.AddStream("p.bin", new MemoryStream(new byte[500_000]), 500_000);
            w.Finish();
        }

        Assert.NotEmpty(percents);
    }

    [Fact]
    public void PasswordRequired_Event_Fires_WhenNoPreset()
    {
        var zip = Path.Combine(_dir, "ask.zip");
        var password = TestSecrets.Fixed(21);
        using (var w = GeneralZipWriter.CreateNew(zip, o =>
               {
                   o.EncryptionAlgorithm = "SM4-GM";
                   o.Password = password;
               }))
        {
            w.AddStream("need-pw.txt", new MemoryStream(new byte[1024]), 1024);
            w.Finish();
        }

        var asked = 0;
        using var r = GeneralZipReader.Open(zip);
        r.PasswordRequired += (_, e) =>
        {
            asked++;
            e.Password = password;
        };

        var dest = Path.Combine(_dir, "out-pw");
        var result = r.ExtractToDirectory(dest);
        Assert.Equal(1, asked);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal(1024, new FileInfo(Path.Combine(dest, "need-pw.txt")).Length);
    }

    [Fact]
    public void PasswordRequired_Cancel_Throws()
    {
        var zip = Path.Combine(_dir, "cancel-pw.zip");
        using (var w = GeneralZipWriter.CreateNew(zip, o =>
               {
                   o.EncryptionAlgorithm = "WinZipAES256";
                   o.Password = TestSecrets.Fixed(22);
               }))
        {
            w.AddStream("locked.txt", new MemoryStream(new byte[128]), 128);
            w.Finish();
        }

        using var r = GeneralZipReader.Open(zip);
        r.PasswordRequired += (_, e) => e.Cancel = true;

        Assert.Throws<PasswordRequiredException>(() =>
        {
            using var s = r.OpenEntryStream(r.Entries[0]);
            s.Read(new byte[16], 0, 16);
        });
    }

    [Fact]
    public void WrongPassword_RetriesViaEvent()
    {
        var zip = Path.Combine(_dir, "retry.zip");
        var right = TestSecrets.Fixed(23);
        using (var w = GeneralZipWriter.CreateNew(zip, o =>
               {
                   o.EncryptionAlgorithm = "SM4-GM";
                   o.Password = right;
               }))
        {
            w.AddStream("r.txt", new MemoryStream(new byte[512]), 512);
            w.Finish();
        }

        var attempts = new List<int>();
        using var r = GeneralZipReader.Open(zip, o => o.Password = TestSecrets.Wrong(right));
        r.PasswordRequired += (_, e) =>
        {
            attempts.Add(e.Attempt);
            e.Password = right; // 事件给出正确口令
        };

        var dest = Path.Combine(_dir, "out-retry");
        var result = r.ExtractToDirectory(dest);

        Assert.Equal(new[] { 1 }, attempts); // 预置口令失效后，事件第 1 次外部询问给出正确口令
        Assert.Equal(0, result.FailedCount);
    }

    [Fact]
    public void OverwriteAsk_Event_Decision()
    {
        var zip = Path.Combine(_dir, "ow.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("f.txt", new MemoryStream(Encoding.UTF8.GetBytes("new")), 3);
            w.Finish();
        }

        var dest = Path.Combine(_dir, "out-ow");
        Directory.CreateDirectory(dest);
        File.WriteAllText(Path.Combine(dest, "f.txt"), "old");

        var asked = 0;
        using var r = GeneralZipReader.Open(zip);
        r.OverwriteQuery += (_, e) =>
        {
            asked++;
            e.Action = OverwriteAction.Overwrite;
        };

        var result = r.ExtractToDirectory(dest, new ExtractionOptions { OverwritePolicy = OverwritePolicy.Ask });
        Assert.Equal(1, asked);
        Assert.Equal("new", File.ReadAllText(Path.Combine(dest, "f.txt")));

        // Skip 决策
        asked = 0;
        using (var r2 = GeneralZipReader.Open(zip))
        {
            r2.OverwriteQuery += (_, e) =>
            {
                asked++;
                e.Action = OverwriteAction.Skip;
            };

            var result2 = r2.ExtractToDirectory(dest, new ExtractionOptions { OverwritePolicy = OverwritePolicy.Ask });
            Assert.Equal(1, asked);
            Assert.Equal(1, result2.SkippedCount);
            Assert.Equal("new", File.ReadAllText(Path.Combine(dest, "f.txt"))); // 未被覆盖
        }
    }

    [Fact]
    public void ErrorPolicy_SkipAll_Continues()
    {
        // 构造第二个条目损坏的包：先写正常包再截断中部数据区
        var zip = BuildCorruptedSecondEntry();

        using var r = GeneralZipReader.Open(zip);
        var result = r.ExtractToDirectory(Path.Combine(_dir, "out-skip"),
            new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll });

        Assert.Equal(1, result.FailedCount);
        Assert.Equal(1, result.ProcessedCount); // 第一个条目成功
    }

    [Fact]
    public void ErrorPolicy_RaiseEvent_RetryAndSkip()
    {
        var zip = BuildCorruptedSecondEntry();
        var decisions = 0;

        using var r = GeneralZipReader.Open(zip);
        r.ErrorReport += (_, e) =>
        {
            decisions++;
            e.Action = ErrorAction.Skip;
        };

        var result = r.ExtractToDirectory(Path.Combine(_dir, "out-raise"),
            new ExtractionOptions { ErrorPolicy = ErrorPolicy.RaiseEvent });

        Assert.Equal(1, decisions);
        Assert.Equal(1, result.FailedCount);
    }

    [Fact]
    public void Cancellation_StopsExtraction()
    {
        var zip = Path.Combine(_dir, "cancel.zip");
        using (var w = GeneralZipWriter.CreateNew(zip))
        {
            w.AddStream("a.bin", new MemoryStream(new byte[300_000]), 300_000);
            w.AddStream("b.bin", new MemoryStream(new byte[300_000]), 300_000);
            w.Finish();
        }

        using var cts = new CancellationTokenSource();
        var cancelledAt = 0;
        using var r = GeneralZipReader.Open(zip);
        r.EntryCompleted += (_, _) =>
        {
            cancelledAt++;
            cts.Cancel();
        };

        Assert.ThrowsAny<OperationCanceledException>(() =>
            r.ExtractToDirectory(Path.Combine(_dir, "out-cancel"), null, cts.Token));
        Assert.Equal(1, cancelledAt);
    }

    [Fact]
    public void TestAll_ReportsFailures_WithSkipAll()
    {
        var zip = BuildCorruptedSecondEntry();
        using var r = GeneralZipReader.Open(zip);
        var result = r.TestAll(new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll });
        Assert.Equal(1, result.FailedCount);
    }

    /// <summary>构造两个条目、第二个条目数据区被破坏的包。</summary>
    private string BuildCorruptedSecondEntry()
    {
        var good = Path.Combine(_dir, $"src-good-{Guid.NewGuid():N}.zip");
        using (var w = GeneralZipWriter.CreateNew(good))
        {
            w.AddStream("1st.txt", new MemoryStream(Encoding.UTF8.GetBytes("fine")), 4);
            w.AddStream("2nd.txt", new MemoryStream(new byte[4096]), 4096);
            w.Finish();
        }

        // 找到第二个 local header（PK\x03\x04）并破坏其后的数据
        var bytes = File.ReadAllBytes(good);
        var first = IndexOf(bytes, 0, Sig(0x50, 0x4B, 0x03, 0x04));
        var second = IndexOf(bytes, first + 4, Sig(0x50, 0x4B, 0x03, 0x04));
        var corruptAt = second + 30 + 7; // local header 30B + 文件名 "2nd.txt"
        bytes[corruptAt] ^= 0xFF;

        var broken = Path.Combine(_dir, $"src-broken-{Guid.NewGuid():N}.zip");
        File.WriteAllBytes(broken, bytes);
        return broken;
    }

    private static int IndexOf(byte[] haystack, int start, byte[] needle)
    {
        for (var i = start; i <= haystack.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            }

            if (ok) return i;
        }

        return -1;
    }

    private static byte[] Sig(byte a, byte b, byte c, byte d) => new[] { a, b, c, d };
}
