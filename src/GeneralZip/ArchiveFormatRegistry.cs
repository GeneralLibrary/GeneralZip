using System;
using System.Collections.Generic;
using System.IO;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// 格式提供者注册表。内置格式预注册；<see cref="Register"/> 注入第三方格式。
/// 探测顺序：签名优先（按注册顺序），扩展名兜底。线程安全。
/// </summary>
public sealed class ArchiveFormatRegistry
{
    private readonly object _lock = new();
    private readonly List<IArchiveFormat> _formats = new();

    internal ArchiveFormatRegistry(bool populateBuiltins)
    {
        if (populateBuiltins)
        {
            Register(new Formats.Zip.ZipFormat());
            Register(new Formats.Tar.TarFormat());
            Register(new Formats.Tar.TarGzFormat());
            Register(new Formats.Tar.TarBz2Format());
            Register(new Formats.Codecs.GZipFormat());
            Register(new Formats.Codecs.BZip2Format());
            Register(new Formats.Codecs.XzFormat());
            Register(new Formats.Codecs.ZstdFormat());
            Register(new Formats.Codecs.Lz4Format());
        }
    }

    public static ArchiveFormatRegistry Default { get; } = new(populateBuiltins: true);

    /// <summary>注册格式提供者（重复注册同名格式将覆盖旧的）。</summary>
    public void Register(IArchiveFormat format)
    {
        if (format == null) throw new ArgumentNullException(nameof(format));

        lock (_lock)
        {
            _formats.RemoveAll(f => string.Equals(f.Info.Name, format.Info.Name, StringComparison.OrdinalIgnoreCase));
            _formats.Add(format);
        }
    }

    public bool Unregister(string formatName)
    {
        lock (_lock)
        {
            return _formats.RemoveAll(f => string.Equals(f.Info.Name, formatName, StringComparison.OrdinalIgnoreCase)) > 0;
        }
    }

    public IReadOnlyList<IArchiveFormat> Snapshot()
    {
        lock (_lock)
        {
            return new List<IArchiveFormat>(_formats);
        }
    }

    public IArchiveFormat? FindByName(string name)
    {
        lock (_lock)
        {
            return _formats.Find(f => string.Equals(f.Info.Name, name, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>签名探测：依次询问各提供者，首个命中者胜出。</summary>
    public IArchiveFormat? Detect(Stream stream)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (!stream.CanRead) throw new ArgumentException("Stream must be readable", nameof(stream));

        IArchiveFormat[] formats;
        lock (_lock)
        {
            formats = _formats.ToArray();
        }

        foreach (var format in formats)
        {
            try
            {
                if (format.MatchesSignature(stream))
                {
                    return format;
                }
            }
            catch (Exception) when (!stream.CanRead)
            {
                throw;
            }
            catch (Exception)
            {
                // 单个提供者探测异常不中断整体探测
            }
        }

        return null;
    }

    /// <summary>
    /// 按文件路径的扩展名匹配。使用后缀匹配（"x.tar.gz" 命中 ".tar.gz" 而非 ".gz"），
    /// 注册顺序优先（复合扩展名格式应先注册）。
    /// </summary>
    public IArchiveFormat? DetectByExtension(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;

        IArchiveFormat[] formats;
        lock (_lock)
        {
            formats = _formats.ToArray();
        }

        var fileName = Path.GetFileName(path);
        foreach (var format in formats)
        {
            foreach (var ext in format.Info.Extensions)
            {
                if (fileName.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                {
                    return format;
                }
            }
        }

        return null;
    }
}
