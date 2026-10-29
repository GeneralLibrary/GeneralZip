using System;
using System.IO;

namespace GeneralZip.Abstractions;

/// <summary>
/// 格式提供者：格式探测 + 打开读写器。
/// 实现要求：无状态、线程安全（每次 Open 返回独立实例），可注册为单例。
/// </summary>
public interface IArchiveFormat
{
    /// <summary>格式元信息。</summary>
    ArchiveFormatInfo Info { get; }

    /// <summary>魔数探测。实现必须只读取 stream 前部并在返回前恢复 Position（流可寻址时）。</summary>
    bool MatchesSignature(Stream stream);

    /// <summary>按扩展名匹配（大小写不敏感，含点）。</summary>
    bool MatchesExtension(string extension);

    /// <summary>打开读取器。实现应在此校验结构完整性（如解析中央目录），惰性处理条目数据。</summary>
    IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options);

    /// <summary>创建新归档写入器。stream 必须可写。</summary>
    IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options);
}
