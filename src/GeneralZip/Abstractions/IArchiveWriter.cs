using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace GeneralZip.Abstractions;

/// <summary>
/// 归档写入器（格式级）。顺序写入模型：条目逐个落盘，Finish 收尾（如 ZIP 中央目录）。
/// 门面层负责事件与进度；实现聚焦格式本身。
/// </summary>
public interface IArchiveWriter : IDisposable, IAsyncDisposable
{
    ArchiveFormatInfo Info { get; }

    /// <summary>写入选项快照（含加密提供者等）。</summary>
    ArchiveWriteOptions Options { get; }

    /// <summary>把内容流写入为新条目。entryName 使用 '/' 分隔。</summary>
    void AddEntry(string entryName, Stream content, ArchiveEntryMetadata metadata, CancellationToken cancellationToken);

    /// <summary>写入一个目录占位条目（部分格式支持；不支持时实现可忽略）。</summary>
    void AddDirectoryEntry(string entryName, ArchiveEntryMetadata metadata);

    /// <summary>完成归档（写中央目录/索引、刷新缓冲）。重复调用为无操作。</summary>
    void Finish(CancellationToken cancellationToken);

    /// <summary>异步完成归档。</summary>
    Task FinishAsync(CancellationToken cancellationToken);
}

/// <summary>条目元数据。</summary>
public sealed class ArchiveEntryMetadata
{
    /// <summary>未压缩大小；未知（流式）为 -1。</summary>
    public long Size { get; set; } = -1;

    public DateTimeOffset? LastWriteTime { get; set; }

    public uint? Crc32 { get; set; }

    public string? Comment { get; set; }

    /// <summary>归档内不可见的外部源路径（供实现优化，如原生核心直接落盘文件）；门面层设置。</summary>
    public string? SourcePath { get; set; }
}
