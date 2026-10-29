using System;
using System.IO;

namespace GeneralZip.Abstractions;

/// <summary>解压时目标文件已存在（或目录项冲突）的策略。</summary>
public enum OverwritePolicy
{
    /// <summary>抛出 IOException。</summary>
    Throw = 0,

    /// <summary>直接覆盖。</summary>
    Overwrite = 1,

    /// <summary>跳过该条目。</summary>
    Skip = 2,

    /// <summary>触发 <see cref="Events.OverwriteQueryEventArgs"/> 事件由调用方决定。</summary>
    Ask = 3,

    /// <summary>自动重命名（name (2).ext 形式）。</summary>
    Rename = 4,
}

/// <summary>事件应答的覆盖动作。</summary>
public enum OverwriteAction
{
    Overwrite = 0,
    Skip = 1,
    Rename = 2,

    /// <summary>中止整个解压操作（等效取消）。</summary>
    Abort = 3,
}

/// <summary>条目级错误的默认策略。</summary>
public enum ErrorPolicy
{
    /// <summary>立即抛出（默认，最严格）。</summary>
    Throw = 0,

    /// <summary>记录并跳过出错条目，继续其余条目。</summary>
    SkipAll = 1,

    /// <summary>触发 <see cref="Events.ArchiveErrorEventArgs"/> 事件，由处理器决定重试/跳过/中止。</summary>
    RaiseEvent = 2,
}

/// <summary>事件应答的错误动作。</summary>
public enum ErrorAction
{
    Retry = 0,
    Skip = 1,
    Abort = 2,
}

/// <summary>解压选项。</summary>
public sealed class ExtractionOptions
{
    public OverwritePolicy OverwritePolicy { get; set; } = OverwritePolicy.Throw;

    public ErrorPolicy ErrorPolicy { get; set; } = ErrorPolicy.Throw;

    /// <summary>覆盖事件内自动重命名的上限次数，超出后抛出。默认 64。</summary>
    public int MaxRenameAttempts { get; set; } = 64;

    /// <summary>只解压满足条件的条目（目录条目除外）。null = 全部。</summary>
    public Predicate<IArchiveEntry>? Filter { get; set; }

    /// <summary>解压根目录下的扁平化：忽略条目内部路径，全部落在目标目录。默认 false。</summary>
    public bool Flatten { get; set; }

    /// <summary>保留文件时间戳（默认 true；部分场景如持续集成可关闭）。</summary>
    public bool PreserveTimestamps { get; set; } = true;

    /// <summary>事件处理器抛出的异常是否透传（默认 false：隔离并按 Skip 处理）。</summary>
    public bool PropagateEventExceptions { get; set; }

    /// <summary>错误重试的最大次数（RaiseEvent 策略下处理器连选 Retry 的上限）。默认 3。</summary>
    public int MaxRetryPerEntry { get; set; } = 3;

    /// <summary>单条目复制缓冲区大小（字节）。默认 81920。</summary>
    public int BufferSize { get; set; } = 81920;
}
