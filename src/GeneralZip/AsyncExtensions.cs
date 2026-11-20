using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// 异步友好扩展（IAsyncEnumerable 条目枚举）。
/// netstandard2.0 经 Microsoft.Bcl.AsyncInterfaces 提供 IAsyncEnumerable。
/// </summary>
public static class GeneralZipAsyncExtensions
{
    /// <summary>以异步流形式枚举归档条目（惰性；取消在条目间生效）。</summary>
    public static async IAsyncEnumerable<IArchiveEntry> EnumerateEntriesAsync(
        this GeneralZipReader reader,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var entry in reader.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;
            await Task.Yield();
        }
    }

    /// <summary>
    /// 异步解压单个条目（同步 IO 经 Task.Run 保持异步语义；事件仍同步触发）。
    /// </summary>
    public static Task<ArchiveResult> ExtractEntryAsync(
        this GeneralZipReader reader,
        IArchiveEntry entry,
        string destinationFilePath,
        ExtractionOptions? options = null,
        CancellationToken cancellationToken = default)
        => Task.Run(
            () => reader.ExtractEntry(entry, destinationFilePath, options, cancellationToken),
            cancellationToken);
}
