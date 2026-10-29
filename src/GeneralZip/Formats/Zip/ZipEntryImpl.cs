using System;
using System.Text;
using GeneralZip.Abstractions;

namespace GeneralZip.Formats.Zip;

/// <summary>ZIP 条目的 IArchiveEntry 视图。</summary>
internal sealed class ZipEntryView : IArchiveEntry
{
    private readonly ZipCentralEntry _central;
    private readonly string _fullName;
    private readonly string? _encryptionAlgorithm;

    public ZipEntryView(ZipCentralEntry central, string fullName, string? encodingAlgorithmName)
    {
        _central = central;
        _fullName = fullName;
        _encryptionAlgorithm = encodingAlgorithmName;
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

    internal ZipCentralEntry Central => _central;
}
