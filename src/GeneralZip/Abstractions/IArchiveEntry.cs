using System;

namespace GeneralZip.Abstractions;

/// <summary>归档条目的统一视图。所有格式映射到同一模型，路径统一使用 '/' 分隔。</summary>
public interface IArchiveEntry
{
    /// <summary>完整条目路径（'/' 分隔，不含起始斜杠）。目录条目通常以 '/' 结尾。</summary>
    string FullName { get; }

    /// <summary>文件名部分（最后一段）。</summary>
    string Name { get; }

    /// <summary>解压后字节数；未知时为 -1。</summary>
    long Size { get; }

    /// <summary>压缩/加密后占归档的字节数；未知时为 -1。</summary>
    long CompressedSize { get; }

    DateTimeOffset? LastWriteTime { get; }

    bool IsDirectory { get; }

    /// <summary>条目数据是否加密（需要口令才能解压）。</summary>
    bool IsEncrypted { get; }

    /// <summary>加密算法标识（如 "WinZipAES256"、"SM4-GM"）；未加密为 null。</summary>
    string? EncryptionAlgorithm { get; }

    /// <summary>CRC-32（未压缩数据）；格式不支持或加密隐藏时为 null。</summary>
    uint? Crc32 { get; }

    string? Comment { get; }
}
