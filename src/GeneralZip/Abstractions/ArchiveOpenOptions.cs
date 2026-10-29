using System;
using System.Text;

namespace GeneralZip.Abstractions;

/// <summary>打开归档的选项。</summary>
public sealed class ArchiveOpenOptions
{
    /// <summary>预置口令；等价于一个总是返回该口令的 <see cref="IPasswordProvider"/>（仅首次询问生效）。</summary>
    public string? Password { get; set; }

    /// <summary>
    /// 动态口令供给器（弹窗等交互场景）。设置后 <see cref="Password"/> 失效。
    /// 返回 null 表示放弃解密。
    /// </summary>
    public IPasswordProvider? PasswordProvider { get; set; }

    /// <summary>单条目/整包口令最大尝试次数，超过则抛出。默认 3。</summary>
    public int MaxPasswordAttempts { get; set; } = 3;

    /// <summary>条目名编码。null 时由格式自判（ZIP 优先 UTF-8 标志，否则回退 IBM437）。</summary>
    public Encoding? EntryNameEncoding { get; set; }

    /// <summary>进度接收器（可选）。与门面层事件并行可用。</summary>
    public IProgress<ArchiveProgress>? Progress { get; set; }

    /// <summary>来源文件名（门面层从路径填充；单文件编解码格式用于推导条目名）。</summary>
    public string? SourceName { get; set; }
}
