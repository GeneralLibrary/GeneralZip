using System;
using System.IO;
using System.Threading;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// 重打包核心：把源归档条目忠实复制到目标归档（读出→重写语义）。
/// Append / Remove / Convert 三个门面操作共用。条目名称、大小、时间戳、注释、目录占位保留；
/// 加密状态不保留（源条目被解密后按目标写入选项重新加密）。
/// </summary>
internal static class Repack
{
    /// <summary>把 reader 的全部条目（满足 keepEntry 的）复制进 writer。返回 (复制数, 跳过数)。</summary>
    public static (int copied, int skipped) CopyEntries(
        GeneralZipReader reader,
        GeneralZipWriter writer,
        Func<IArchiveEntry, bool>? keepEntry,
        CancellationToken cancellationToken)
    {
        var copied = 0;
        var skipped = 0;
        foreach (var entry in reader.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (keepEntry != null && !keepEntry(entry))
            {
                skipped++;
                continue;
            }

            if (entry.IsDirectory)
            {
                writer.AddDirectoryEntry(entry.FullName, entry.LastWriteTime);
                copied++;
                continue;
            }

            var meta = new ArchiveEntryMetadata
            {
                Size = entry.Size,
                LastWriteTime = entry.LastWriteTime,
                Comment = entry.Comment,
            };

            using var content = reader.OpenEntryStream(entry);
            writer.AddStream(entry.FullName, content, meta);
            copied++;
        }

        return (copied, skipped);
    }

    /// <summary>把文件或目录源（CompressAsync 语义）追加进 writer。</summary>
    public static void AddSourcePath(GeneralZipWriter writer, string sourcePath, CancellationToken cancellationToken)
    {
        if (File.Exists(sourcePath))
        {
            writer.AddFileAsync(sourcePath, null, cancellationToken).GetAwaiter().GetResult();
            return;
        }

        if (Directory.Exists(sourcePath))
        {
            var name = new System.IO.DirectoryInfo(sourcePath).Name;
            var hasChildren = System.IO.Directory.EnumerateFileSystemEntries(sourcePath).GetEnumerator().MoveNext();
            writer.AddDirectoryAsync(sourcePath, hasChildren ? name : null, cancellationToken: cancellationToken)
                .GetAwaiter().GetResult();
            return;
        }

        throw new FileNotFoundException("Source path does not exist", sourcePath);
    }

    /// <summary>在目标文件所在目录生成同后缀名临时文件路径（保留 ".tar.gz" 类复合后缀以正确推断格式）。</summary>
    public static string TempSiblingPath(string targetPath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(targetPath)) ?? ".";
        var name = Path.GetFileName(targetPath);
        return Path.Combine(dir, $"gz-rewrite-{Guid.NewGuid():N}-{name}");
    }

    /// <summary>覆盖式移动（netstandard2.0 无 File.Move(string,string,bool)）。</summary>
    public static void MoveOverwrite(string sourcePath, string targetPath)
    {
#if NET8_0_OR_GREATER
        File.Move(sourcePath, targetPath, overwrite: true);
#else
        if (File.Exists(targetPath))
        {
            File.Delete(targetPath);
        }

        File.Move(sourcePath, targetPath);
#endif
    }
}
