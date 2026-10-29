using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Native;

/// <summary>原生条目视图（由列表 JSON 反序列化）。</summary>
internal sealed class NativeEntryView : IArchiveEntry
{
    public string FullName { get; set; } = string.Empty;

    public long Size { get; set; } = -1;

    public bool IsDirectory { get; set; }

    public long MtimeWindowsFileTime { get; set; }

    public bool HasMtime { get; set; }

    public string Name
    {
        get
        {
            var idx = FullName.LastIndexOf('/');
            return idx >= 0 ? FullName.Substring(idx + 1) : FullName;
        }
    }

    public long CompressedSize => -1;

    public DateTimeOffset? LastWriteTime =>
        HasMtime ? DateTimeOffset.FromFileTime(MtimeWindowsFileTime) : null;

    public bool IsEncrypted { get; set; }

    public string? EncryptionAlgorithm { get; set; }

    public uint? Crc32 => null;

    public string? Comment => null;

    /// <summary>解析核心返回的条目 JSON：[{"name":..,"size":..,"isDir":..,"mtime":..,"hasMtime":..}]。</summary>
    public static List<NativeEntryView> Parse(string json)
    {
        var list = new List<NativeEntryView>();
        using var doc = JsonDocument.Parse(json);
        foreach (var element in doc.RootElement.EnumerateArray())
        {
            var name = element.GetProperty("name").GetString() ?? string.Empty;
            list.Add(new NativeEntryView
            {
                FullName = name.Replace('\\', '/'),
                Size = element.TryGetProperty("size", out var size) ? size.GetInt64() : -1,
                IsDirectory = element.TryGetProperty("isDir", out var dir) && dir.GetBoolean(),
                MtimeWindowsFileTime = element.TryGetProperty("mtime", out var mtime) ? mtime.GetInt64() : 0,
                HasMtime = element.TryGetProperty("hasMtime", out var has) && has.GetBoolean(),
            });
        }

        return list;
    }
}

/// <summary>原生调用状态 → 异常映射（口令错误由调用方结合 PasswordProvider 重试）。</summary>
internal static class NativeCall
{
    public static Exception ToException(int status, string context, string? entryName = null)
    {
        var detail = GzpNative.LastError();
        return status switch
        {
            GzpNative.GzpErrPassword => new InvalidPasswordException(entryName ?? context),
            GzpNative.GzpErrNotFound => new FileNotFoundException($"{context}: {detail}"),
            GzpNative.GzpErrFormat => new ArchiveCorruptedException($"{context}: {detail}", entryName),
            GzpNative.GzpErrUnsupported => new NotSupportedException($"{context}: {detail}"),
            GzpNative.GzpErrPanic => new ArchiveException($"{context}: 原生核心内部错误: {detail}", entryName),
            GzpNative.GzpErrArg => new ArgumentException($"{context}: 参数错误: {detail}"),
            GzpNative.GzpErrBuffer => new ArchiveException($"{context}: 缓冲区不足", entryName),
            _ => new ArchiveException($"{context}: {detail}", entryName),
        };
    }

    /// <summary>两段式条目列表获取（先探长度，再取数据）。</summary>
    public static string ListJson(bool rar, string path, byte[]? password)
    {
        var pwLen = password != null ? (uint)(password.Length - 1) : 0;

        var status = rar
            ? GzpNative.gzp_rar_list_json(path, password, pwLen, null, 0, out var needed)
            : GzpNative.gzp_7z_list_json(path, password, pwLen, null, 0, out needed);

        if (status == GzpNative.GzpOk)
        {
            return "[]";
        }

        if (status != GzpNative.GzpErrBuffer)
        {
            throw ToException(status, $"{(rar ? "RAR" : "7z")} 列表失败: {path}");
        }

        var buffer = new byte[needed];
        status = rar
            ? GzpNative.gzp_rar_list_json(path, password, pwLen, buffer, (uint)buffer.Length, out _)
            : GzpNative.gzp_7z_list_json(path, password, pwLen, buffer, (uint)buffer.Length, out _);

        if (status != GzpNative.GzpOk)
        {
            throw ToException(status, $"{(rar ? "RAR" : "7z")} 列表失败: {path}");
        }

        return System.Text.Encoding.UTF8.GetString(buffer);
    }
}

/// <summary>口令解析：预置口令 → 提供者（重试计数由提供者内部管理）。</summary>
internal static class PasswordResolver
{
    public static byte[]? Resolve(ArchiveOpenOptions options, string? entryName)
    {
        if (options.PasswordProvider != null)
        {
            var pw = options.PasswordProvider.GetPassword(new PasswordRequest(
                PasswordScope.WholeArchive, entryName, 1, options.MaxPasswordAttempts));
            return GzpNative.PasswordBytes(pw);
        }

        return GzpNative.PasswordBytes(options.Password);
    }
}
