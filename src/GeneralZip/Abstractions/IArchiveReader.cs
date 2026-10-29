using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace GeneralZip.Abstractions;

/// <summary>
/// 归档读取器（格式级）。事件与策略由门面层统一编排，实现保持简单：
/// 列出条目、按条目打开解压流、提供整包解压的默认实现。
/// 实现不线程安全：同一实例的操作应串行。
/// </summary>
public interface IArchiveReader : IDisposable
{
    ArchiveFormatInfo Format { get; }

    /// <summary>归档内全部条目（打开时解析完成）。</summary>
    IReadOnlyList<IArchiveEntry> Entries { get; }

    /// <summary>归档是否包含加密条目（或整体加密）。</summary>
    bool IsEncrypted { get; }

    /// <summary>
    /// 打开条目的解压流（已解密、已解压，顺序读取）。调用方负责 Dispose。
    /// 流支持顺序读取；Length 可用时反映解压后大小。
    /// </summary>
    Stream OpenEntryStream(IArchiveEntry entry);

    /// <summary>把条目流复制到目标流（门面层用于解压到文件/校验）。</summary>
    void CopyEntryTo(IArchiveEntry entry, Stream destination, CancellationToken cancellationToken);
}
