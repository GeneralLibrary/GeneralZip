using System;
using System.Collections.Generic;

namespace GeneralZip.Abstractions;

/// <summary>格式元信息（名称、扩展名、能力）。提供者无状态，本对象可作为单例公开。</summary>
public sealed class ArchiveFormatInfo
{
    public ArchiveFormatInfo(
        string name,
        IReadOnlyList<string> extensions,
        FormatCapabilities capabilities,
        string? description = null)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Extensions = extensions ?? throw new ArgumentNullException(nameof(extensions));
        Capabilities = capabilities;
        Description = description;
    }

    /// <summary>格式短名，如 "ZIP"、"7Z"、"RAR"。</summary>
    public string Name { get; }

    /// <summary>典型扩展名（小写、含点），如 [".zip"]。</summary>
    public IReadOnlyList<string> Extensions { get; }

    /// <summary>能力位。</summary>
    public FormatCapabilities Capabilities { get; }

    public string? Description { get; }

    public bool CanRead => (Capabilities & FormatCapabilities.Read) != 0;
    public bool CanWrite => (Capabilities & FormatCapabilities.Write) != 0;
    public bool CanReadEncrypted => (Capabilities & FormatCapabilities.EncryptedRead) != 0;
    public bool CanWriteEncrypted => (Capabilities & FormatCapabilities.EncryptedWrite) != 0;

    public override string ToString() => Name;
}
