using System;

namespace GeneralZip;

/// <summary>操作阶段。</summary>
public enum ArchivePhase
{
    /// <summary>解析归档结构 / 枚举条目。</summary>
    Analyzing,

    /// <summary>压缩写入中。</summary>
    Compressing,

    /// <summary>解压读取中。</summary>
    Decompressing,

    /// <summary>完整性测试中。</summary>
    Testing,

    /// <summary>收尾（写中央目录/索引、刷缓冲）。</summary>
    Finalizing,
}

/// <summary>
/// 进度快照（不可变）。同时投递给事件与 <see cref="IProgress{ArchiveProgress}"/>。
/// 无法计算的数值以 null 表达（流式未知大小等）。
/// </summary>
public sealed class ArchiveProgress
{
    public ArchiveProgress(
        ArchivePhase phase,
        string? currentEntry,
        long entriesCompleted,
        long? entriesTotal,
        long bytesProcessed,
        long? bytesTotal,
        double? percent,
        double? bytesPerSecond,
        TimeSpan? eta)
    {
        Phase = phase;
        CurrentEntry = currentEntry;
        EntriesCompleted = entriesCompleted;
        EntriesTotal = entriesTotal;
        BytesProcessed = bytesProcessed;
        BytesTotal = bytesTotal;
        Percent = percent;
        BytesPerSecond = bytesPerSecond;
        Eta = eta;
    }

    public ArchivePhase Phase { get; }

    /// <summary>当前处理的条目名。</summary>
    public string? CurrentEntry { get; }

    /// <summary>已完成条目数。</summary>
    public long EntriesCompleted { get; }

    /// <summary>条目总数（未知为 null）。</summary>
    public long? EntriesTotal { get; }

    /// <summary>已处理未压缩字节。</summary>
    public long BytesProcessed { get; }

    /// <summary>未压缩字节总数（未知为 null）。</summary>
    public long? BytesTotal { get; }

    /// <summary>整体百分比 0~100（无法计算为 null）。</summary>
    public double? Percent { get; }

    /// <summary>吞吐（字节/秒）。</summary>
    public double? BytesPerSecond { get; }

    /// <summary>预计剩余时间。</summary>
    public TimeSpan? Eta { get; }

    public override string ToString()
    {
        var pct = Percent?.ToString("F1") ?? "-";
        var speed = BytesPerSecond.HasValue ? $"{BytesPerSecond / 1024:F0} KB/s" : "-";
        return $"[{Phase}] {CurrentEntry ?? "-"} {pct}% ({speed})";
    }
}
