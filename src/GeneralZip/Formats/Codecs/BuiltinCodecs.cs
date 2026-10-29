using System;
using System.IO;
using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Formats.Codecs;

/// <summary>
/// 原生编解码路由辅助：单文件编解码格式（BZ2/XZ/ZSTD/LZ4）经 Rust 原生核心
/// 以"临时文件整段编解码"方式实现；核心缺失时抛出带部署指引的异常。
/// </summary>
internal static class NativeCodecRouter
{
    public static void EnsureCore()
    {
        // 通过桥接委托间接访问原生核心，避免核心包对 Native 包的编译期依赖：
        // GeneralZip.Native 在 Initialize 时注入 NativeBridge 的实现。
        if (!NativeBridgeProbe.IsAvailableSafe())
        {
            throw new NativeCoreMissingException(
                "该编解码格式需要 Rust 原生核心（generalzip_native）。" +
                "请引用 GeneralZip.Native 包并在启动时调用 GeneralZipNative.Initialize()，" +
                "或将归档转存为 ZIP/TAR.GZ 等纯托管格式。");
        }
    }

    internal static bool IsCoreAvailable() => NativeBridge.IsAvailable?.Invoke() ?? false;

    internal static void Compress(string codec, string source, string destination)
    {
        var handler = NativeBridge.Compress;
        if (handler == null || !handler(codec, source, destination))
        {
            throw new NativeCoreMissingException(
                $"原生核心不支持 {codec} 编码或未加载。请引用 GeneralZip.Native 并调用 GeneralZipNative.Initialize()。");
        }
    }

    internal static void Decompress(string codec, string source, string destination)
    {
        var handler = NativeBridge.Decompress;
        if (handler == null || !handler(codec, source, destination))
        {
            throw new NativeCoreMissingException(
                $"原生核心不支持 {codec} 解码或未加载。请引用 GeneralZip.Native 并调用 GeneralZipNative.Initialize()。");
        }
    }
}

/// <summary>
/// 原生核心桥接点：GeneralZip.Native 包在 Initialize 时注入实现。
/// 核心包经此间接使用原生能力，保持"核心零 P/Invoke"的架构边界。
/// </summary>
public static class NativeBridge
{
    /// <summary>原生核心是否已加载。GeneralZipNative.Initialize 注入。</summary>
    public static Func<bool>? IsAvailable { get; set; }

    /// <summary>整文件编解码：codec ∈ {bzip2, xz, zstd, lz4}。返回是否成功（false = 不支持该 codec）。</summary>
    public static Func<string, string, string, bool>? Compress { get; set; }

    /// <summary>整文件解码。返回是否成功。</summary>
    public static Func<string, string, string, bool>? Decompress { get; set; }
}

/// <summary>原生核心可用性（桥接未注入时视为不可用）。</summary>
public static class NativeBridgeProbe
{
    public static bool IsAvailableSafe() => NativeBridge.IsAvailable?.Invoke() ?? false;
}

/// <summary>gzip 单文件格式（.gz）。读/写使用 .NET 内置 GZipStream（微软官方，零第三方依赖）。</summary>
public sealed class GZipFormat : SingleFileCodecFormat
{
    public GZipFormat()
        : base("GZIP", new[] { ".gz", ".gzip" }, ".gz", "gzip 单文件压缩", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) =>
        new System.IO.Compression.GZipStream(source, System.IO.Compression.CompressionMode.Decompress, leaveOpen: false);

    protected override Stream OpenCompress(Stream destination) =>
        new System.IO.Compression.GZipStream(destination, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 2 && prefix[0] == 0x1F && prefix[1] == 0x8B;
}

/// <summary>
/// bzip2 单文件格式（.bz2）。编解码经 Rust 原生核心（libbz2-rs 纯 Rust 实现）；核心缺失时不可用。
/// </summary>
public sealed class BZip2Format : SingleFileCodecFormat
{
    public BZip2Format()
        : base("BZIP2", new[] { ".bz2", ".bzip2" }, ".bz2", "bzip2 单文件压缩（原生核心）", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => WrapWithNative("bzip2", source, decompress: true);

    protected override Stream OpenCompress(Stream destination) => WrapWithNative("bzip2", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 3 && prefix[0] == (byte)'B' && prefix[1] == (byte)'Z' && prefix[2] == (byte)'h';

    internal static Stream WrapWithNative(string codec, Stream stream, bool decompress)
    {
        NativeCodecRouter.EnsureCore();
        return new NativeTempCodecStream(stream, codec,
            decompress ? NativeCodecMode.Decompress : NativeCodecMode.Compress);
    }
}

/// <summary>
/// xz 单文件格式（.xz）。编解码经 Rust 原生核心（LZMA2）；核心缺失时不可用。
/// </summary>
public sealed class XzFormat : SingleFileCodecFormat
{
    public XzFormat()
        : base("XZ", new[] { ".xz" }, ".xz", "xz（LZMA2）单文件压缩（原生核心）", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => BZip2Format.WrapWithNative("xz", source, decompress: true);

    protected override Stream OpenCompress(Stream destination) => BZip2Format.WrapWithNative("xz", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 6 && prefix[0] == 0xFD && prefix[1] == 0x37 && prefix[2] == 0x7A
           && prefix[3] == 0x58 && prefix[4] == 0x5A && prefix[5] == 0x00;
}

/// <summary>
/// Zstandard 单文件格式（.zst）。编解码经 Rust 原生核心（纯 Rust 实现）；核心缺失时不可用。
/// </summary>
public sealed class ZstdFormat : SingleFileCodecFormat
{
    public ZstdFormat()
        : base("ZSTD", new[] { ".zst", ".zstd" }, ".zst", "Zstandard 单文件压缩（原生核心）", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => BZip2Format.WrapWithNative("zstd", source, decompress: true);

    protected override Stream OpenCompress(Stream destination) => BZip2Format.WrapWithNative("zstd", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 4 && prefix[0] == 0x28 && prefix[1] == 0xB5 && prefix[2] == 0x2F && prefix[3] == 0xFD;
}

/// <summary>
/// LZ4 帧格式（.lz4）。编解码经 Rust 原生核心（lz4_flex 纯 Rust 实现）；核心缺失时不可用。
/// </summary>
public sealed class Lz4Format : SingleFileCodecFormat
{
    public Lz4Format()
        : base("LZ4", new[] { ".lz4" }, ".lz4", "LZ4 帧格式单文件压缩（原生核心）", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => BZip2Format.WrapWithNative("lz4", source, decompress: true);

    protected override Stream OpenCompress(Stream destination) => BZip2Format.WrapWithNative("lz4", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 4 && prefix[0] == 0x04 && prefix[1] == 0x22 && prefix[2] == 0x4D && prefix[3] == 0x18;
}
