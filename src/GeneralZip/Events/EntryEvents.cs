using System;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>条目开始/完成事件参数。</summary>
public class EntryEventArgs : EventArgs
{
    public EntryEventArgs(IArchiveEntry entry)
    {
        Entry = entry ?? throw new ArgumentNullException(nameof(entry));
    }

    public IArchiveEntry Entry { get; }

    /// <summary>条目名（<see cref="IArchiveEntry.FullName"/> 的快捷方式）。</summary>
    public string EntryName => Entry.FullName;
}

/// <summary>条目内字节级进度事件参数。</summary>
public sealed class EntryProgressEventArgs : EntryEventArgs
{
    public EntryProgressEventArgs(IArchiveEntry entry, long bytesProcessed, long? bytesTotal)
        : base(entry)
    {
        BytesProcessed = bytesProcessed;
        BytesTotal = bytesTotal;
    }

    public long BytesProcessed { get; }

    public long? BytesTotal { get; }

    /// <summary>条目内百分比（未知大小为 null）。</summary>
    public double? Percent => BytesTotal is > 0 ? Math.Min(100.0, BytesProcessed * 100.0 / BytesTotal.Value) : null;
}

/// <summary>条目失败事件参数。</summary>
public sealed class EntryFailedEventArgs : EntryEventArgs
{
    public EntryFailedEventArgs(IArchiveEntry entry, Exception exception)
        : base(entry)
    {
        Exception = exception ?? throw new ArgumentNullException(nameof(exception));
    }

    public Exception Exception { get; }
}
