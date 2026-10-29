using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Native;

/// <summary>
/// RAR 格式提供者（经 Rust 原生核心，unrar 封装）。仅读取（RAR 压缩算法专有）。
/// 仅当原生核心以 `rar` feature 构建时注册（能力协商）。
/// </summary>
public sealed class RarNativeFormat : IArchiveFormat
{
    internal RarNativeFormat() { }

    public ArchiveFormatInfo Info { get; } = new(
        "RAR",
        new[] { ".rar" },
        FormatCapabilities.Read | FormatCapabilities.EncryptedRead | FormatCapabilities.SeekableRead,
        "RAR4/RAR5 read (Rust native core; password decryption supported)");

    public bool MatchesSignature(Stream stream)
    {
        long restore = -1;
        if (stream.CanSeek) restore = stream.Position;
        try
        {
            var arr = new byte[8];
            var total = 0;
            while (total < 8)
            {
                var n = stream.Read(arr, total, 8 - total);
                if (n <= 0) break;
                total += n;
            }

            if (total < 7) return false;
            // RAR4: 52 61 72 21 1A 07 00    RAR5: 52 61 72 21 1A 07 01 00
            if (arr[0] != 0x52 || arr[1] != 0x61 || arr[2] != 0x72 || arr[3] != 0x21
                || arr[4] != 0x1A || arr[5] != 0x07)
            {
                return false;
            }

            return total >= 7;
        }
        finally
        {
            if (restore >= 0) stream.Position = restore;
        }
    }

    public bool MatchesExtension(string extension) =>
        extension.Equals(".rar", StringComparison.OrdinalIgnoreCase);

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        NativeCoreLoader.EnsureLoaded();
        return new RarNativeReader(stream, options);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
    {
        throw new NotSupportedException("RAR is a proprietary compression format and read-only (no compliant library can create RAR archives)");
    }
}

/// <summary>RAR 读取器（列表/解压经原生核心）。</summary>
internal sealed class RarNativeReader : IArchiveReader
{
    private readonly Stream _stream;
    private readonly ArchiveOpenOptions _options;
    private readonly string _tempPath;
    private readonly bool _ownsTemp;
    private List<NativeEntryView>? _entries;

    public RarNativeReader(Stream stream, ArchiveOpenOptions options)
    {
        _stream = stream;
        _options = options;

        if (stream is FileStream fs)
        {
            _tempPath = fs.Name;
            _ownsTemp = false;
        }
        else
        {
            _tempPath = Path.Combine(Path.GetTempPath(), $"gzp-{Guid.NewGuid():N}.rar");
            using (var target = new FileStream(_tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                if (stream.CanSeek) stream.Position = 0;
                stream.CopyTo(target, 65536);
            }

            _ownsTemp = true;
        }
    }

    public ArchiveFormatInfo Format { get; } = new(
        "RAR", new[] { ".rar" },
        FormatCapabilities.Read | FormatCapabilities.EncryptedRead | FormatCapabilities.SeekableRead,
        "RAR (native core)");

    public IReadOnlyList<IArchiveEntry> Entries
    {
        get
        {
            if (_entries != null) return _entries;

            var password = PasswordResolver.Resolve(_options, null);
            var json = NativeCall.ListJson(rar: true, _tempPath, password);
            _entries = NativeEntryView.Parse(json);
            return _entries;
        }
    }

    public bool IsEncrypted
    {
        get
        {
            _ = Entries;
            return false; // RAR 分条目加密在解压时体现
        }
    }

    public Stream OpenEntryStream(IArchiveEntry entry)
    {
        if (_entries == null || !TryIndexOf(entry, out var index))
        {
            throw new ArgumentException("Entry does not belong to this archive", nameof(entry));
        }

        var password = PasswordResolver.Resolve(_options, entry.FullName);
        var tempFile = Path.Combine(Path.GetTempPath(), $"gzp-{Guid.NewGuid():N}.bin");

        var status = GzpNative.gzp_rar_extract(
            _tempPath, password, password != null ? (uint)(password.Length - 1) : 0,
            index, tempFile, null, IntPtr.Zero);

        if (status != GzpNative.GzpOk)
        {
            SevenZipNativeReader.TryDelete(tempFile);
            throw NativeCall.ToException(status, "RAR entry extraction failed", entry.FullName);
        }

        return new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.Read, 65536,
            FileOptions.DeleteOnClose | FileOptions.SequentialScan);
    }

    public void CopyEntryTo(IArchiveEntry entry, Stream destination, CancellationToken cancellationToken)
    {
        using var source = OpenEntryStream(entry);
        var buffer = new byte[81920];
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            destination.Write(buffer, 0, read);
        }
    }

    private bool TryIndexOf(IArchiveEntry entry, out long index)
    {
        var entries = Entries;
        for (var i = 0; i < entries.Count; i++)
        {
            if (ReferenceEquals(entries[i], entry))
            {
                index = i;
                return true;
            }
        }

        index = -1;
        return false;
    }

    public void Dispose()
    {
        if (_ownsTemp)
        {
            SevenZipNativeReader.TryDelete(_tempPath);
        }
    }
}
