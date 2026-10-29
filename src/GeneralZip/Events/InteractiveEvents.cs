using System;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>口令请求事件参数。处理器应设置 <see cref="Password"/>；设为 null/空 且 Cancel=true 则放弃。</summary>
public sealed class PasswordRequiredEventArgs : EventArgs
{
    public PasswordRequiredEventArgs(PasswordRequest request)
    {
        Request = request ?? throw new ArgumentNullException(nameof(request));
    }

    public PasswordRequest Request { get; }

    public PasswordScope Scope => Request.Scope;

    public string? EntryName => Request.EntryName;

    /// <summary>第几次尝试（1 起）。组件在口令错误后以 Attempt+1 重新触发本事件。</summary>
    public int Attempt => Request.Attempt;

    /// <summary>处理器提供的口令。非空即视为已应答。</summary>
    public string? Password { get; set; }

    /// <summary>设为 true 放弃解密（将抛 PasswordRequiredException）。</summary>
    public bool Cancel { get; set; }

    internal bool HasAnswer => !Cancel && !string.IsNullOrEmpty(Password);
}

/// <summary>覆盖询问事件参数（OverwritePolicy.Ask 时触发）。</summary>
public sealed class OverwriteQueryEventArgs : EventArgs
{
    public OverwriteQueryEventArgs(string entryName, string targetPath, long size, DateTimeOffset? lastWriteTime)
    {
        EntryName = entryName;
        TargetPath = targetPath;
        Size = size;
        LastWriteTime = lastWriteTime;
    }

    public string EntryName { get; }

    /// <summary>将被覆盖的目标文件完整路径。</summary>
    public string TargetPath { get; }

    /// <summary>条目解压后大小。</summary>
    public long Size { get; }

    public DateTimeOffset? LastWriteTime { get; }

    /// <summary>处理器决策。默认 Skip（保守：不改磁盘）。</summary>
    public OverwriteAction Action { get; set; } = OverwriteAction.Skip;
}

/// <summary>错误上报事件参数（ErrorPolicy.RaiseEvent 时触发）。</summary>
public sealed class ArchiveErrorEventArgs : EventArgs
{
    public ArchiveErrorEventArgs(string? entryName, Exception exception, int retryCount, int maxRetry)
    {
        EntryName = entryName;
        Exception = exception ?? throw new ArgumentNullException(nameof(exception));
        RetryCount = retryCount;
        MaxRetry = maxRetry;
    }

    public string? EntryName { get; }

    public Exception Exception { get; }

    /// <summary>本条目已重试次数。</summary>
    public int RetryCount { get; }

    /// <summary>重试上限（ExtractionOptions.MaxRetryPerEntry）。</summary>
    public int MaxRetry { get; }

    /// <summary>处理器决策。默认 Skip。</summary>
    public ErrorAction Action { get; set; } = ErrorAction.Skip;
}
