using System;
using System.Collections.Generic;

namespace GeneralZip;

/// <summary>单条失败记录。</summary>
public sealed class FailedEntry
{
    public FailedEntry(string entryName, Exception exception)
    {
        EntryName = entryName ?? throw new ArgumentNullException(nameof(entryName));
        Exception = exception ?? throw new ArgumentNullException(nameof(exception));
    }

    public string EntryName { get; }

    public Exception Exception { get; }

    public override string ToString() => $"{EntryName}: {Exception.Message}";
}

/// <summary>批量操作结果摘要。</summary>
public sealed class ArchiveResult
{
    internal static ArchiveResult Empty() => new();

    public long ProcessedCount { get; internal set; }

    public long SkippedCount { get; internal set; }

    public long FailedCount => Failures.Count;

    public IReadOnlyList<FailedEntry> Failures { get; internal set; } = Array.Empty<FailedEntry>();

    /// <summary>是否因覆盖事件选择 Abort / 取消而提前结束。</summary>
    public bool Aborted { get; internal set; }

    public bool Success => FailedCount == 0;
}
