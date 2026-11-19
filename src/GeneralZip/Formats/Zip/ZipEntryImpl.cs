using System;
using System.Text;
using GeneralZip.Abstractions;

namespace GeneralZip.Formats.Zip;

/// <summary>ZIP 条目的 IArchiveEntry 视图（Unix host 归档额外携带 st_mode）。</summary>
internal sealed class ZipEntryView : IArchiveEntry, IUnixEntry
{
    private readonly ZipCentralEntry _central;
    private readonly string _fullName;
    private readonly string? _encryptionAlgorithm;
    private readonly uint? _unixMode;

    public ZipEntryView(ZipCentralEntry central, string fullName, string? encodingAlgorithmName)
    {
        _central = central;
        _fullName = fullName;
        _encryptionAlgorithm = encodingAlgorithmName;

        // Unix host（3）与 macOS host（19）的 ExternalAttributes 高 16 位为 st_mode
        var host = central.VersionMadeBy >> 8;
        if (host == 3 || host == 19)
        {
            _unixMode = central.ExternalAttributes >> 16;
        }
    }

    public string FullName => _fullName;

    public string Name
    {
        get
        {
            var idx = _fullName.LastIndexOf('/');
            return idx >= 0 ? _fullName.Substring(idx + 1) : _fullName;
        }
    }

    public long Size => _central.UncompressedSize;

    public long CompressedSize => _central.CompressedSize;

    public DateTimeOffset? LastWriteTime => ZipTime.FromDos(_central.DosTime, _central.DosDate);

    public bool IsDirectory => _fullName.EndsWith("/", StringComparison.Ordinal);

    public bool IsEncrypted => _encryptionAlgorithm != null;

    public string? EncryptionAlgorithm => _encryptionAlgorithm;

    /// <summary>加密条目（AE-2 / SM4-GM）的 CRC 恒为 0，视为不可用。</summary>
    public uint? Crc32 => _encryptionAlgorithm == null || _central.Crc32 != 0 ? _central.Crc32 : null;

    public string? Comment => _central.DecodeComment(null);

    /// <summary>Unix host 归档携带 st_mode（符号链接判定：(mode &amp; 0xF000) == 0xA000）。</summary>
    public uint? UnixMode => _unixMode;

    /// <summary>ZIP 的符号链接目标以条目内容承载，头部不携带 → 恒 null（见 IUnixEntry 文档）。</summary>
    public string? SymlinkTarget => null;

    internal ZipCentralEntry Central => _central;
}
