using System;

namespace GeneralZip;

/// <summary>组件异常基类。尽可能携带出错条目名。</summary>
public class ArchiveException : Exception
{
    public ArchiveException(string message, string? entryName = null, Exception? inner = null)
        : base(entryName == null ? message : $"{message}（条目：{entryName}）", inner)
    {
        EntryName = entryName;
    }

    /// <summary>出错条目名（若与特定条目相关）。</summary>
    public string? EntryName { get; }
}

/// <summary>格式无法识别或本组件不支持。</summary>
public sealed class UnsupportedFormatException : ArchiveException
{
    public UnsupportedFormatException(string message, string? entryName = null, Exception? inner = null)
        : base(message, entryName, inner)
    {
    }
}

/// <summary>Rust 原生核心未部署（7z/RAR 等原生格式不可用）。异常消息含部署指引。</summary>
public sealed class NativeCoreMissingException : ArchiveException
{
    public NativeCoreMissingException(string message)
        : base(message)
    {
    }
}

/// <summary>遇到加密内容但无口令可用（未预置且事件未应答/放弃）。</summary>
public sealed class PasswordRequiredException : ArchiveException
{
    public PasswordRequiredException(string? entryName)
        : base("该内容已加密，需要提供口令。请设置 options.Password、订阅 PasswordRequired 事件，或经由 IPasswordProvider 提供。", entryName)
    {
    }
}

/// <summary>口令错误。</summary>
public sealed class InvalidPasswordException : ArchiveException
{
    public InvalidPasswordException(string? entryName, int attempt = 0, Exception? inner = null)
        : base(attempt > 0 ? $"口令错误（第 {attempt} 次尝试）。" : "口令错误。", entryName, inner)
    {
        Attempt = attempt;
    }

    /// <summary>第几次尝试（0 = 未计数）。</summary>
    public int Attempt { get; }
}

/// <summary>归档损坏：CRC/HMAC 校验失败、结构非法、意外截断等。</summary>
public sealed class ArchiveCorruptedException : ArchiveException
{
    public ArchiveCorruptedException(string message, string? entryName = null, Exception? inner = null)
        : base(message, entryName, inner)
    {
    }
}
