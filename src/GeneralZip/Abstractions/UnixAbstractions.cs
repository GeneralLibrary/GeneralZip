using System;

namespace GeneralZip.Abstractions;

/// <summary>
/// Unix 属性条目视图（可选能力接口）：ZIP（Unix host 的 ExternalAttributes）与
/// TAR（ustar mode 字段）在读取时实现。
/// <para>符号链接判定：<see cref="UnixMode"/> 类型位 <c>(mode &amp; 0xF000) == 0xA000</c>；
/// 目标路径：<see cref="SymlinkTarget"/>（TAR 在头部携带；ZIP 等以条目内容承载，此处为 null）。</para>
/// </summary>
public interface IUnixEntry
{
    /// <summary>Unix st_mode（含文件类型位与权限位）；格式未携带时为 null。</summary>
    uint? UnixMode { get; }

    /// <summary>符号链接目标（条目为符号链接且格式在头部携带目标时）；否则 null。</summary>
    string? SymlinkTarget { get; }
}

/// <summary>
/// 符号链接写入能力（可选接口）：ZIP（S_IFLNK 条目 + Unix ExternalAttributes）与
/// TAR（typeflag '2' + linkname）实现。门面 <see cref="GeneralZipWriter.AddSymlink"/> 依此分派。
/// </summary>
public interface IArchiveSymlinkWriter
{
    /// <summary>写入一个符号链接条目（target 为链接目标路径字符串）。</summary>
    void AddSymlink(string entryName, string target, ArchiveEntryMetadata metadata);
}

/// <summary>解压时的符号链接处理策略。</summary>
public enum SymlinkPolicy
{
    /// <summary>跳过符号链接条目（默认：防 zip-slip 类攻击的保守选择）。</summary>
    Skip = 0,

    /// <summary>按条目创建符号链接（Windows 需要开发者模式/管理员权限；失败降级为普通文件写入目标路径文本）。</summary>
    Preserve = 1,
}
