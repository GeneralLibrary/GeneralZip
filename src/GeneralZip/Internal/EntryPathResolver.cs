using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using GeneralZip.Abstractions;

namespace GeneralZip.Internal;

/// <summary>
/// 条目路径解析：'/' 分隔 → 目标文件系统路径。
/// 防目录穿越（zip-slip）：绝对路径与越过根的 ".." 记为不安全条目。
/// </summary>
internal static class EntryPathResolver
{
    public static readonly char[] DirectorySeparators = { '/', '\\' };

    /// <summary>解析目标路径；不安全条目返回 null（调用方按错误处理）。</summary>
    public static string? Resolve(string destinationDirectory, IArchiveEntry entry, bool flatten)
    {
        var name = entry.FullName;

        // 绝对路径 / 盘符 → 拒绝
        if (Path.IsPathRooted(name) || (name.Length >= 2 && name[1] == ':'))
        {
            return null;
        }

        if (flatten)
        {
            var fileName = SanitizeSegment(SplitName(name).name);
            return string.IsNullOrEmpty(fileName) ? null : Path.Combine(destinationDirectory, fileName);
        }

        var parts = name.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;

        var segments = new List<string>(parts.Length);
        foreach (var raw in parts)
        {
            if (raw == ".") continue;
            if (raw == "..") return null; // 越根穿越 → 拒绝
            var s = SanitizeSegment(raw);
            if (string.IsNullOrEmpty(s)) return null;
            segments.Add(s);
        }

        if (segments.Count == 0) return null;

        var combined = Path.Combine(segments.Prepend(destinationDirectory).ToArray());
        return combined;
    }

    public static bool ContainsReparsePoint(string rootDirectory, string targetPath)
    {
        var root = NormalizeRoot(rootDirectory);
        var target = Path.GetFullPath(targetPath);
        var comparison = Path.DirectorySeparatorChar == '\\' ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            ? root
            : root + Path.DirectorySeparatorChar;
        if (!target.Equals(root, comparison) && !target.StartsWith(rootPrefix, comparison))
        {
            return true;
        }

        var relative = target.Length == root.Length ? string.Empty : target.Substring(rootPrefix.Length);
        var current = root;
        if (IsReparsePoint(current)) return true;
        foreach (var segment in relative.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (IsReparsePoint(current)) return true;
        }

        return false;
    }

    public static bool LinkTargetStaysWithinRoot(string rootDirectory, string linkPath, string target)
    {
        if (Path.IsPathRooted(target) || (target.Length >= 2 && target[1] == ':'))
        {
            return false;
        }

        var resolved = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(linkPath) ?? rootDirectory, target));
        var comparison = Path.DirectorySeparatorChar == '\\' ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var root = NormalizeRoot(rootDirectory);
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            ? root
            : root + Path.DirectorySeparatorChar;
        return (resolved.Equals(root, comparison) || resolved.StartsWith(rootPrefix, comparison))
            && !ContainsReparsePoint(root, resolved);
    }

    private static string NormalizeRoot(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ?? string.Empty;
        var trimmed = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return trimmed.Length < root.Length ? root : trimmed;
    }

    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        catch (IOException) { return false; }
    }

    /// <summary>保留末段文件名。</summary>
    public static (string dir, string name) SplitName(string fullName)
    {
        var trimmed = fullName.TrimEnd('/');
        var idx = trimmed.LastIndexOf('/');
        return idx >= 0
            ? (trimmed.Substring(0, idx), trimmed.Substring(idx + 1))
            : (string.Empty, trimmed);
    }

    /// <summary>清洗单个路径段中的非法字符（跨平台保守集合）。</summary>
    public static string SanitizeSegment(string segment)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = segment.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (Array.IndexOf(invalid, chars[i]) >= 0)
            {
                chars[i] = '_';
            }
        }

        var cleaned = new string(chars).TrimEnd(' ', '.');
        return cleaned.Length == 0 ? "_" : cleaned;
    }

    /// <summary>生成 "name (2).ext" 形式的可用路径。</summary>
    public static string NextAvailableName(string path, int maxAttempts)
    {
        var dir = Path.GetDirectoryName(path) ?? string.Empty;
        var file = Path.GetFileName(path);
        var ext = Path.GetExtension(file);
        var stem = ext.Length > 0 ? file.Substring(0, file.Length - ext.Length) : file;

        for (var i = 2; i <= maxAttempts + 1; i++)
        {
            var candidate = Path.Combine(dir, $"{stem} ({i}){ext}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException($"Auto-rename failed (exceeded limit of {maxAttempts}): {path}");
    }

    /// <summary>归档内条目名规范化：'/' 分隔、去起始分隔符。</summary>
    public static string NormalizeEntryName(string name)
    {
        var n = name.Replace('\\', '/').TrimStart('/');
        while (n.Contains("//"))
        {
            n = n.Replace("//", "/");
        }

        return n;
    }
}
