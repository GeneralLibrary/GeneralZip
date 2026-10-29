using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Formats.Tar;

/// <summary>
/// Shared implementation for the TAR family of format providers: TAR / TAR.GZ / TAR.BZ2.
/// The TAR container is this project's own ustar implementation; the compression
/// wrapper (gzip/bzip2) is injected by subclasses.
/// </summary>
public abstract class TarFormatBase : IArchiveFormat
{
    protected TarFormatBase(string name, string[] extensions, string? description)
    {
        Info = new ArchiveFormatInfo(
            name,
            extensions,
            FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.SeekableRead,
            description);
    }

    public ArchiveFormatInfo Info { get; }

    /// <summary>Outer decompression wrapper (gzip/bzip2 etc.); pure TAR returns the stream unchanged.</summary>
    protected abstract Stream WrapDecompress(Stream source);

    /// <summary>Outer compression wrapper; pure TAR returns the stream unchanged.</summary>
    protected abstract Stream WrapCompress(Stream destination);

    /// <summary>Signature probe for the outer compression format; pure TAR checks ustar directly.</summary>
    protected abstract bool MatchesOuterSignature(byte[] prefix, int length);

    public bool MatchesSignature(Stream stream)
    {
        long restorePos = -1;
        if (stream.CanSeek) restorePos = stream.Position;

        try
        {
            // Pure TAR needs 262 bytes to locate the ustar magic;
            // outer compression formats need enough compressed prefix to decode the first 262 bytes.
            // bzip2/xz are decoded whole-file by the native core and cannot be partially decoded —
            // a too-short prefix would fail to decode and cause a misdetection, so read up to 16MB;
            // larger files are corrected by the caller's extension fallback logic.
            var readSize = IsPureTar()
                ? 262
                : (int)Math.Min(Math.Max(stream.Length, 1), 16L * 1024 * 1024);
            if (readSize <= 0) return false;

            var prefix = new byte[readSize];
            var len = FillPrefix(stream, prefix);
            if (!MatchesOuterSignature(prefix, len)) return false;

            if (IsPureTar())
            {
                return TarIo.HasUstarMagic(prefix, len);
            }

            using var inner = WrapDecompress(new MemoryStream(prefix, 0, len, writable: false));
            var tail = new byte[262];
            var total = 0;
            int n;
            while (total < tail.Length && (n = inner.Read(tail, total, tail.Length - total)) > 0)
            {
                total += n;
            }

            return total >= 262 && TarIo.HasUstarMagic(tail, total);
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (restorePos >= 0) stream.Position = restorePos;
        }
    }

    protected virtual bool IsPureTar() => false;

    public bool MatchesExtension(string extension)
    {
        foreach (var ext in Info.Extensions)
        {
            if (extension.Equals(ext, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    public IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options)
    {
        Stream OpenDecompressed()
        {
            if (stream.CanSeek)
            {
                stream.Position = 0;
            }

            return WrapDecompress(stream);
        }

        return new TarReader(OpenDecompressed, Info, options);
    }

    public IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options)
    {
        return new TarWriter(WrapCompress(stream), Info, options);
    }

    private static int FillPrefix(Stream stream, byte[] prefix)
    {
        var total = 0;
        while (total < prefix.Length)
        {
            var n = stream.Read(prefix, total, prefix.Length - total);
            if (n <= 0) break;
            total += n;
        }

        return total;
    }
}

/// <summary>TAR entry view.</summary>
internal sealed class TarEntryView : IArchiveEntry
{
    public TarEntryView(string fullName, long size, DateTimeOffset? mtime, bool isDirectory)
    {
        FullName = fullName;
        Size = size;
        LastWriteTime = mtime;
        IsDirectory = isDirectory;
    }

    public string FullName { get; }
    public string Name
    {
        get
        {
            var idx = FullName.LastIndexOf('/');
            return idx >= 0 ? FullName.Substring(idx + 1) : FullName;
        }
    }

    public long Size { get; }
    public long CompressedSize => -1;
    public DateTimeOffset? LastWriteTime { get; }
    public bool IsDirectory { get; }
    public bool IsEncrypted => false;
    public string? EncryptionAlgorithm => null;
    public uint? Crc32 => null;
    public string? Comment => null;
}

/// <summary>TAR reader (over a decompression wrapper stream).</summary>
internal sealed class TarReader : IArchiveReader
{
    private readonly List<TarEntryView> _entries = new();
    private Stream _inner;
    private readonly Func<Stream> _reopenDecompressed;
    private TarStreamReader? _sequential; // sequential cursor for non-seekable mode

    public TarReader(Func<Stream> openDecompressed, ArchiveFormatInfo info, ArchiveOpenOptions options)
    {
        Format = info;
        _reopenDecompressed = openDecompressed;
        _inner = openDecompressed();

        using (var probe = OpenTarStream())
        {
            TarHeaderInfo? entry;
            while ((entry = probe.GetNextEntry()) != null)
            {
                var name = entry.Name.TrimStart('/');
                if (name.Length == 0) continue;
                if (entry.IsDirectory && !name.EndsWith("/", StringComparison.Ordinal))
                {
                    name += "/";
                }

                _entries.Add(new TarEntryView(
                    name,
                    entry.Size,
                    entry.ModTime == default ? null : entry.ModTime,
                    name.EndsWith("/", StringComparison.Ordinal)));
            }
        }

        if (_inner.CanSeek)
        {
            _inner.Position = 0; // seekable: entry streams re-position on demand
        }
        else
        {
            // non-seekable (e.g. tar.gz pipe stream): the probe exhausted the wrapper —
            // rebuild it and use it as the sequential cursor
            _inner.Dispose();
            _inner = openDecompressed();
            _sequential = OpenTarStream();
        }
    }

    private TarStreamReader OpenTarStream()
    {
        return new TarStreamReader(_inner, Encoding.UTF8);
    }

    public ArchiveFormatInfo Format { get; }

    public IReadOnlyList<IArchiveEntry> Entries => _entries;

    public bool IsEncrypted => false;

    public Stream OpenEntryStream(IArchiveEntry entry)
    {
        if (_inner.CanSeek)
        {
            _inner.Position = 0;
            return TarEntryStream.OpenSeekable(OpenTarStream(), entry.FullName);
        }

        return TarEntryStream.OpenSequential(_sequential ?? throw new InvalidOperationException(), entry.FullName, _entries, entry);
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

    public void Dispose()
    {
        _sequential?.Dispose();
        _inner.Dispose();
    }
}

/// <summary>
/// Single-entry sequential read stream.
/// Seekable mode: each open creates a fresh reader advanced to the target entry (random access).
/// Sequential mode: shares one reader; entries must be opened in order.
/// </summary>
internal sealed class TarEntryStream : Stream
{
    private readonly TarStreamReader _reader;
    private readonly long _size;
    private long _remaining;
    private bool _initialized;
    private readonly string _target;
    private readonly int _sequenceIndex;

    private TarEntryStream(TarStreamReader reader, long size, string target, int sequenceIndex)
    {
        _reader = reader;
        _size = size;
        _remaining = size;
        _target = target;
        _sequenceIndex = sequenceIndex;
    }

    public static TarEntryStream OpenSeekable(TarStreamReader reader, string target)
    {
        var size = Locate(reader, target);
        var stream = new TarEntryStream(reader, size, target, -1);
        stream._initialized = true; // Locate already positioned the cursor at the entry data
        stream._remaining = size;
        return stream;
    }

    public static TarEntryStream OpenSequential(TarStreamReader reader, string target, IReadOnlyList<TarEntryView> entries, IArchiveEntry entry)
    {
        var index = -1;
        for (var i = 0; i < entries.Count; i++)
        {
            if (ReferenceEquals(entries[i], entry)) { index = i; break; }
        }

        if (index < 0)
        {
            throw new ArgumentException("Entry does not belong to this archive", nameof(entry));
        }

        return new TarEntryStream(reader, entry.Size, target, index);
    }

    private static long Locate(TarStreamReader reader, string target)
    {
        TarHeaderInfo? e;
        while ((e = reader.GetNextEntry()) != null)
        {
            var name = e.Name.TrimStart('/');
            if (!name.EndsWith("/", StringComparison.Ordinal) && name == target)
            {
                return e.Size;
            }
        }

        throw new ArchiveCorruptedException($"Entry not found in TAR: {target}");
    }

    private void EnsureInitialized()
    {
        if (_initialized) return;
        _initialized = true;

        // Sequential mode only (seekable mode was positioned in OpenSeekable).
        // The cursor counter lives on the shared TarStreamReader.
        while (true)
        {
            var upcoming = _reader.EntriesReturned; // index of the entry this call returns
            if (upcoming > _sequenceIndex)
            {
                throw new ArchiveCorruptedException($"Sequential TAR cursor already passed target entry ({_sequenceIndex})");
            }

            var e = _reader.GetNextEntry();
            if (e == null)
            {
                throw new ArchiveCorruptedException($"Entry not found in TAR: {_target}");
            }

            if (upcoming == _sequenceIndex)
            {
                _remaining = e.Size;
                return;
            }
        }
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _size;
    public override long Position { get => _size - _remaining; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        EnsureInitialized();
        if (_remaining <= 0) return 0;

        var toRead = (int)Math.Min(count, _remaining);
        var n = _reader.ReadCurrentEntryData(buffer, offset, toRead);
        if (n <= 0)
        {
            throw new ArchiveCorruptedException($"TAR entry data unexpectedly truncated: {_target}");
        }

        _remaining -= n;
        if (_remaining <= 0)
        {
            _reader.FinishCurrentEntry();
        }

        return n;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>TAR writer (over a compression wrapper stream). TAR requires known entry sizes.</summary>
internal sealed class TarWriter : IArchiveWriter
{
    private readonly Stream _inner;
    private readonly TarStreamWriter _tar;
    private readonly ArchiveWriteOptions _options;
    private bool _finished;

    public TarWriter(Stream compressed, ArchiveFormatInfo info, ArchiveWriteOptions options)
    {
        Info = info;
        _inner = compressed;
        _options = options;
        _tar = new TarStreamWriter(compressed, options.EntryNameEncoding);
    }

    public ArchiveFormatInfo Info { get; }

    public ArchiveWriteOptions Options => _options;

    public void AddDirectoryEntry(string entryName, ArchiveEntryMetadata metadata)
    {
        var name = Normalize(entryName).TrimEnd('/');
        _tar.PutNextEntry(name + "/", 0, (metadata.LastWriteTime ?? DateTimeOffset.Now).UtcDateTime, 493, isDirectory: true); // 0755
        _tar.CloseEntry();
    }

    public void AddEntry(string entryName, Stream content, ArchiveEntryMetadata metadata, CancellationToken cancellationToken)
    {
        if (!content.CanSeek && metadata.Size < 0)
        {
            throw new NotSupportedException("The TAR format requires a known entry size: provide metadata.Size for non-seekable streams");
        }

        var size = metadata.Size >= 0 ? metadata.Size : content.Length;
        var name = Normalize(entryName);

        _tar.PutNextEntry(name, size, (metadata.LastWriteTime ?? DateTimeOffset.Now).UtcDateTime, 420, isDirectory: false); // 0644

        var buffer = new byte[81920];
        long remaining = size;
        int read;
        while (remaining > 0 && (read = content.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining))) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _tar.Write(buffer, 0, read);
            remaining -= read;
        }

        if (remaining > 0)
        {
            throw new IOException($"Source stream ran out of data: {entryName} declared {size} bytes but fewer were available");
        }

        _tar.CloseEntry();
    }

    public void Finish(CancellationToken cancellationToken)
    {
        if (_finished) return;
        _finished = true;
        _tar.Finish();
        _inner.Flush();
    }

    public Task FinishAsync(CancellationToken cancellationToken)
    {
        Finish(cancellationToken);
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return default;
    }

    private static string Normalize(string name)
    {
        var n = name.Replace('\\', '/').TrimStart('/');
        while (n.StartsWith("/", StringComparison.Ordinal)) n = n.Substring(1);
        return n;
    }

    public void Dispose()
    {
        if (!_finished)
        {
            try { Finish(CancellationToken.None); } catch { /* do not mask the original exception */ }
        }

        _inner.Dispose();
    }
}

/// <summary>Plain TAR format.</summary>
public sealed class TarFormat : TarFormatBase
{
    public TarFormat() : base("TAR", new[] { ".tar" }, "TAR (ustar)")
    {
    }

    protected override Stream WrapDecompress(Stream source) => source;

    protected override Stream WrapCompress(Stream destination) => destination;

    protected override bool MatchesOuterSignature(byte[] prefix, int length) => true;

    protected override bool IsPureTar() => true;
}

/// <summary>TAR.GZ (gzip-wrapped tar; gzip uses the .NET built-in GZipStream).</summary>
public sealed class TarGzFormat : TarFormatBase
{
    public TarGzFormat() : base("TAR.GZ", new[] { ".tar.gz", ".tgz" }, "gzip-compressed TAR")
    {
    }

    protected override Stream WrapDecompress(Stream source) =>
        new System.IO.Compression.GZipStream(source, System.IO.Compression.CompressionMode.Decompress, leaveOpen: true);

    protected override Stream WrapCompress(Stream destination) =>
        new System.IO.Compression.GZipStream(destination, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true);

    protected override bool MatchesOuterSignature(byte[] prefix, int length)
        => length >= 2 && prefix[0] == 0x1F && prefix[1] == 0x8B;
}

/// <summary>
/// TAR.BZ2 (bzip2-wrapped tar). bzip2 codecs go through the Rust native core
/// (libbz2-rs pure-Rust implementation); unavailable when the core is missing.
/// </summary>
public sealed class TarBz2Format : TarFormatBase
{
    public TarBz2Format() : base("TAR.BZ2", new[] { ".tar.bz2", ".tbz2", ".tbz" }, "bzip2-compressed TAR")
    {
    }

    protected override Stream WrapDecompress(Stream source) =>
        Formats.Codecs.BZip2Format.WrapWithNative("bzip2", source, decompress: true);

    protected override Stream WrapCompress(Stream destination) =>
        Formats.Codecs.BZip2Format.WrapWithNative("bzip2", destination, decompress: false);

    protected override bool MatchesOuterSignature(byte[] prefix, int length)
        => length >= 3 && prefix[0] == (byte)'B' && prefix[1] == (byte)'Z' && prefix[2] == (byte)'h';
}
