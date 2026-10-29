using System;

namespace GeneralZip.Abstractions;

/// <summary>格式能力位。提供者据此声明自身支持的操作组合。</summary>
[Flags]
public enum FormatCapabilities
{
    None = 0,

    /// <summary>可读取（列出条目并解压）。</summary>
    Read = 1,

    /// <summary>可创建新归档。</summary>
    Write = 2,

    /// <summary>可读取加密归档（配合口令）。</summary>
    EncryptedRead = 4,

    /// <summary>可创建加密归档（配合口令）。</summary>
    EncryptedWrite = 8,

    /// <summary>底层流可随机寻址（ZIP 等）；不可寻址格式仅支持顺序流式读取。</summary>
    SeekableRead = 16,

    /// <summary>支持向既有归档追加条目。</summary>
    Append = 32,
}
