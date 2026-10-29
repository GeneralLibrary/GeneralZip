using System;

namespace GeneralZip.Abstractions;

/// <summary>口令请求的作用域。</summary>
public enum PasswordScope
{
    /// <summary>仅当前条目加密（如 ZIP 分条目加密、RAR 分条目）。</summary>
    SingleEntry,

    /// <summary>整包加密（如 7z 头加密、RAR5 头部加密），口令打开归档前即需要。</summary>
    WholeArchive,
}

/// <summary>一次口令请求的描述。</summary>
public sealed class PasswordRequest
{
    public PasswordRequest(PasswordScope scope, string? entryName, int attempt, int maxAttempts)
    {
        Scope = scope;
        EntryName = entryName;
        Attempt = attempt;
        MaxAttempts = maxAttempts;
    }

    public PasswordScope Scope { get; }

    /// <summary>触发请求的条目名；整包加密时为 null。</summary>
    public string? EntryName { get; }

    /// <summary>第几次尝试（从 1 开始）。口令错误后组件会以 Attempt+1 再次询问。</summary>
    public int Attempt { get; }

    /// <summary>组件允许的最大尝试次数（防止 UI 死循环）。</summary>
    public int MaxAttempts { get; }

    public override string ToString() =>
        $"{nameof(Scope)}={Scope}, {nameof(EntryName)}={EntryName}, {nameof(Attempt)}={Attempt}/{MaxAttempts}";
}

/// <summary>
/// 口令供给接口。返回 null 表示放弃（组件抛 <see cref="PasswordRequiredException"/>）。
/// 门面层以事件形式实现本接口；格式实现只依赖本接口。
/// </summary>
public interface IPasswordProvider
{
    string? GetPassword(PasswordRequest request);
}
