using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace GeneralZip.Internal;

/// <summary>
/// 分卷写入流：顺序写满一个卷后自动开下一卷（archive.zip.001/002/...）。
/// 仅支持顺序写（ZIP 写入器即为顺序模型）；Finish 由调用方控制，EOCD 自然落在末卷。
/// </summary>
internal sealed class VolumeSplitStream : Stream
{
    private static readonly Regex VolumeSuffixPattern = new(@"^(?<base>.+)\.(?<num>\d{3,})$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private readonly string _basePath;
    private readonly long _volumeSize;
    private readonly int _buffered;
    private FileStream? _current;
    private int _index; // 当前卷号（从 1 起）
    private long _writtenInVolume;

    public VolumeSplitStream(string basePath, long volumeSize)
    {
        if (volumeSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(volumeSize));
        }

        _basePath = Path.GetFullPath(basePath);
        _volumeSize = volumeSize;
        OpenVolume(1);
    }

    /// <summary>实际产生的卷文件路径（Finish 后可用）。</summary>
    public List<string> WrittenVolumes { get; } = new();

    public string FirstVolumePath => VolumePath(1);

    public void Complete()
    {
        Flush();
        var pattern = Path.GetFileName(_basePath) + ".*";
        var directory = Path.GetDirectoryName(_basePath) ?? string.Empty;
        foreach (var path in Directory.EnumerateFiles(directory, pattern))
        {
            var match = VolumeSuffixPattern.Match(Path.GetFileName(path));
            if (match.Success
                && string.Equals(
                    Path.Combine(directory, match.Groups["base"].Value),
                    _basePath,
                    Path.DirectorySeparatorChar == '\\' ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)
                && int.TryParse(match.Groups["num"].Value, out var number)
                && number > _index)
            {
                File.Delete(path);
            }
        }
    }

    public static bool IsFirstVolumePath(string path)
    {
        var match = VolumeSuffixPattern.Match(Path.GetFileName(path));
        return match.Success && int.TryParse(match.Groups["num"].Value, out var number) && number == 1;
    }

    private string VolumePath(int index) => $"{_basePath}.{index:D3}";

    private void OpenVolume(int index)
    {
        _current?.Dispose();
        var path = VolumePath(index);
        _current = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: false);
        WrittenVolumes.Add(path);
        _index = index;
        _writtenInVolume = 0;
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => _index * _volumeSize + _writtenInVolume; set => throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count)
    {
        var written = 0;
        while (written < count)
        {
            var room = _volumeSize - _writtenInVolume;
            if (room == 0)
            {
                OpenVolume(_index + 1);
                room = _volumeSize;
            }

            var chunk = (int)Math.Min(room, count - written);
            _current!.Write(buffer, offset + written, chunk);
            _writtenInVolume += chunk;
            written += chunk;
        }
    }

    public override void Flush() => _current?.Flush();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _current?.Dispose();
            _current = null;
        }

        base.Dispose(disposing);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>按序拼接多个卷文件的可寻址只读流（读取 x.zip.001/002/... 时使用）。</summary>
internal sealed class MultiVolumeStream : Stream
{
    private readonly List<(FileStream stream, long start, long length)> _parts = new();
    private long _position;

    public MultiVolumeStream(IReadOnlyList<string> paths)
    {
        long start = 0;
        foreach (var path in paths)
        {
            var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
            var length = fs.Length;
            _parts.Add((fs, start, length));
            start += length;
        }

        if (_parts.Count == 0)
        {
            throw new ArgumentException("No volume files", nameof(paths));
        }
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _parts[_parts.Count - 1].start + _parts[_parts.Count - 1].length;
    public override long Position { get => _position; set => _position = value; }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var total = 0;
        while (total < count && _position < Length)
        {
            var (_, start, length) = FindPart(_position);
            var stream = _parts[FindPartIndex(_position)].stream;
            stream.Position = _position - start;
            var read = stream.Read(buffer, offset + total, (int)Math.Min(count - total, length - (_position - start)));
            if (read <= 0)
            {
                break;
            }

            _position += read;
            total += read;
        }

        return total;
    }

    private (int index, long start, long length) FindPart(long position)
    {
        for (var i = 0; i < _parts.Count; i++)
        {
            if (position < _parts[i].start + _parts[i].length)
            {
                return (i, _parts[i].start, _parts[i].length);
            }
        }

        var last = _parts.Count - 1;
        return (last, _parts[last].start, _parts[last].length);
    }

    private int FindPartIndex(long position) => FindPart(position).index;

    public override long Seek(long offset, SeekOrigin origin)
    {
        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0)
        {
            throw new IOException("Seek before begin");
        }

        _position = target;
        return _position;
    }

    public override void Flush() { }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var (stream, _, _) in _parts)
            {
                stream.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>分卷路径识别与枚举。</summary>
internal static class SplitVolumeLocator
{
    private static readonly Regex Pattern = new(@"^(?<base>.+)\.(?<num>\d{3,})$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>识别 *.NNN 分卷序文件；返回全部卷路径（按序）。非分卷返回 null。</summary>
    public static IReadOnlyList<string>? Resolve(string path)
    {
        var match = Pattern.Match(Path.GetFileName(path));
        if (!match.Success)
        {
            return null;
        }

        var firstNum = int.Parse(match.Groups["num"].Value, System.Globalization.CultureInfo.InvariantCulture);
        if (firstNum != 1)
        {
            return null; // 必须从 .001 开始
        }

        var basePath = Path.Combine(
            Path.GetDirectoryName(Path.GetFullPath(path)) ?? string.Empty,
            match.Groups["base"].Value);
        var pad = match.Groups["num"].Value.Length;

        var volumes = new List<string>();
        for (var i = 1; ; i++)
        {
            var part = $"{basePath}.{i.ToString($"D{pad}")}";
            if (!File.Exists(part))
            {
                break;
            }

            volumes.Add(part);
        }

        return volumes.Count >= 2 ? volumes : null;
    }
}
