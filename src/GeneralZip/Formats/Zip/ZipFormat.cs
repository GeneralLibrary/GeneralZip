using System;
using System.IO;
using GeneralZip.Abstractions;

namespace GeneralZip.Formats.Zip;

/// <summary>ZIP 格式提供者（自研引擎）。</summary>
public sealed class ZipFormat : IArchiveFormat
{
    public ArchiveFormatInfo Info { get; } = new(
        "ZIP",
        new[] { ".zip" },
        FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.EncryptedRead |
        FormatCapabilities.EncryptedWrite | FormatCapabilities.SeekableRead | FormatCapabilities.Append,
        "ZIP: Store/Deflate/Zip64 + ZipCrypto/WinZip AES/SM4-GM");

    public bool MatchesSignature(Stream stream)
    {
        // ZIP 魔数：PK\x03\x04（常规）/ PK\x05\x06（空归档）/ PK\x07\x08（分卷标记）
        var buf = new byte[4];
        long restorePos = -1;
        if (stream.CanSeek)
        {
            restorePos = stream.Position;
        }

        try
        {
            var total = 0;
            while (total < 4)
            {
                var n = stream.Read(buf, total, 4 - total);
                if (n <= 0) return false;
                total += n;
            }

            return buf[0] == (byte)'P' && buf[1] == (byte)'K'
                   && ((buf[2] == 0x03 && buf[3] == 0x04)
                       || (buf[2] == 0x05 && buf[3] == 0x06)
                       || (buf[2] == 0x07 && buf[3] == 0x08));
        }
        finally
        {
            if (restorePos >= 0)
            {
                stream.Position = restorePos;
            }
        }
    }

    public bool MatchesExtension(string extension) =>
        extension.Equals(".zip", StringComparison.OrdinalIgnoreCase);

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (!stream.CanRead) throw new ArgumentException("Stream must be readable", nameof(stream));
        return new ZipReader(stream, options, ownsStream: false);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (!stream.CanWrite) throw new ArgumentException("Stream must be writable", nameof(stream));
        return new ZipWriter(stream, options, ownsStream: false);
    }
}
