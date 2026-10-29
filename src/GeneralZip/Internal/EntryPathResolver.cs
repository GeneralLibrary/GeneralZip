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
