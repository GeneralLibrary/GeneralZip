using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using GeneralZip;
using GeneralZip.Abstractions;

namespace GeneralZip.Formats.Codecs;

/// <summary>
/// 原生编解码路由辅助：单文件编解码格式（BZ2/XZ/ZSTD/LZ4/BROTLI）与 ZIP 扩展压缩方法
/// 经 Rust 原生核心的流式回调接口实现（零临时文件转码）；核心缺失时抛出带部署指引的异常。
/// </summary>
internal static class NativeCodecRouter
{
    public static void EnsureCore()
    {
        // 通过桥接委托间接访问原生核心，保持编解码实现与 P/Invoke 细节的边界：
        // NativeBridge 的实现由隐式引导注入（Default 注册表装配时自动调用 Bootstrap）。
        if (!NativeBridgeProbe.IsAvailableSafe())
        {
            // 兜底：默认注册表未被触碰时（自定义注册表场景）桥接尚未注入，显式拉起一次。
            global::GeneralZip.Native.GeneralZipNative.EnsureBridge();
            if (!NativeBridgeProbe.IsAvailableSafe())
            {
                throw new NativeCoreMissingException(
                    "This codec format requires the Rust native core (generalzip_native), which was not found next to the application. " +
                    "Place generalzip_native.dll/.so/.dylib in the app directory or under runtimes/<RID>/native/, " +
                    "or re-save the archive as ZIP/TAR.GZ or another pure-managed format.");
            }
        }
    }

    internal static bool IsCoreAvailable()
    {
        global::GeneralZip.Native.GeneralZipNative.EnsureBridge();
        return NativeBridgeProbe.IsAvailableSafe();
    }

    internal static void Compress(string codec, string source, string destination)
    {
        var handler = NativeBridge.Compress;
        if (handler == null || !handler(codec, source, destination))
        {
            throw new NativeCoreMissingException(
                $"The native core does not support {codec} encoding or is not loaded. Place generalzip_native.dll/.so/.dylib next to the app or under runtimes/<RID>/native/.");
        }
    }

    internal static void Decompress(string codec, string source, string destination)
    {
        var handler = NativeBridge.Decompress;
        if (handler == null || !handler(codec, source, destination))
        {
            throw new NativeCoreMissingException(
                $"The native core does not support {codec} decoding or is not loaded. Place generalzip_native.dll/.so/.dylib next to the app or under runtimes/<RID>/native/.");
        }
    }

    // ---------- 流式（回调推拉）路径 ----------

    /// <summary>回调共享上下文：源/目标流 + 取消 + 异常传递。</summary>
    private sealed class TranscodeContext
    {
        public TranscodeContext(Stream source, Stream destination, CancellationToken cancellationToken, Action<long>? progress)
        {
            Source = source;
            Destination = destination;
            CancellationToken = cancellationToken;
            Progress = progress;
            Buffer = new byte[65536];
        }

        public Stream Source { get; }
        public Stream Destination { get; }
        public CancellationToken CancellationToken { get; }
        public Action<long>? Progress { get; }
        public byte[] Buffer { get; }
        public Exception? Error { get; set; }
    }

    /// <summary>流式压缩：Rust 经回调拉明文、推密文。level 0 = 编解码器默认。</summary>
    internal static void CompressStream(Stream source, Stream destination, string codec, int level, CancellationToken cancellationToken, Action<long>? progress = null)
    {
        EnsureCore();
        RunTranscode(codec, compress: true, source, destination, (uint)level, progress, cancellationToken);
    }

    /// <summary>流式解压：Rust 经回调拉密文、推明文。</summary>
    internal static void DecompressStream(Stream source, Stream destination, string codec, CancellationToken cancellationToken, Action<long>? progress = null)
    {
        EnsureCore();
        RunTranscode(codec, compress: false, source, destination, 0, progress, cancellationToken);
    }

    private static void RunTranscode(string codec, bool compress, Stream source, Stream destination, uint level, Action<long>? progress, CancellationToken cancellationToken)
    {
        var context = new TranscodeContext(source, destination, cancellationToken, progress);
        var handle = GCHandle.Alloc(context);
        try
        {
            global::GeneralZip.Native.GzpNative.GzpCodecReadCallback readCb = OnReadCallback;
            global::GeneralZip.Native.GzpNative.GzpCodecWriteCallback writeCb = OnWriteCallback;

            var status = compress
                ? global::GeneralZip.Native.GzpNative.gzp_codec_crun(codec, level, readCb, writeCb, GCHandle.ToIntPtr(handle))
                : global::GeneralZip.Native.GzpNative.gzp_codec_drun(codec, readCb, writeCb, GCHandle.ToIntPtr(handle));

            if (context.Error != null)
            {
                throw context.Error; // C# 侧异常（含 OperationCanceledException）优先透传
            }

            if (status != global::GeneralZip.Native.GzpNative.GzpOk)
            {
                var lastError = global::GeneralZip.Native.GzpNative.LastError();
                throw global::GeneralZip.Native.NativeCall.ToException(
                    status,
                    $"Native codec stream failed ({codec}, {(compress ? "compress" : "decompress")}): {lastError}");
            }
        }
        finally
        {
            handle.Free();
        }
    }

    private static int OnReadCallback(IntPtr buffer, uint capacity, IntPtr userData)
    {
        var context = (TranscodeContext?)GCHandle.FromIntPtr(userData).Target;
        if (context == null)
        {
            return -1;
        }

        try
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var want = (int)Math.Min(capacity, (uint)context.Buffer.Length);
            var read = context.Source.Read(context.Buffer, 0, want);
            if (read > 0)
            {
                Marshal.Copy(context.Buffer, 0, buffer, read);
            }

            return read;
        }
        catch (Exception ex)
        {
            context.Error ??= ex;
            return -1;
        }
    }

    private static int OnWriteCallback(IntPtr buffer, uint length, IntPtr userData)
    {
        var context = (TranscodeContext?)GCHandle.FromIntPtr(userData).Target;
        if (context == null)
        {
            return -1;
        }

        try
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            // Rust 侧单次 write 可能超过固定缓冲（如编码器整块输出），按长度循环消费
            var remaining = (int)length;
            var offset = 0;
            while (remaining > 0)
            {
                var chunk = Math.Min(remaining, context.Buffer.Length);
                Marshal.Copy(IntPtr.Add(buffer, offset), context.Buffer, 0, chunk);
                context.Destination.Write(context.Buffer, 0, chunk);
                context.Progress?.Invoke(chunk);
                remaining -= chunk;
                offset += chunk;
            }

            return 0;
        }
        catch (Exception ex)
        {
            context.Error ??= ex;
            return -1;
        }
    }
}

/// <summary>
/// 原生核心桥接点：隐式引导（GeneralZipNative.Bootstrap）注入实现。
/// 核心包经此间接使用原生能力，保持"核心零 P/Invoke"的架构边界。
/// </summary>
public static class NativeBridge
{
    /// <summary>原生核心是否已加载。隐式引导注入。</summary>
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
        : base("GZIP", new[] { ".gz", ".gzip" }, "gzip single-file compression", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) =>
        new System.IO.Compression.GZipStream(source, System.IO.Compression.CompressionMode.Decompress, leaveOpen: true);

    internal override Stream OpenCompress(Stream destination) =>
        new System.IO.Compression.GZipStream(destination, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 2 && prefix[0] == 0x1F && prefix[1] == 0x8B;

    internal override string? NativeCodecId => null;
}

/// <summary>
/// bzip2 单文件格式（.bz2）。编解码经 Rust 原生核心（libbz2-rs 纯 Rust 实现）；核心缺失时不可用。
/// </summary>
public sealed class BZip2Format : SingleFileCodecFormat
{
    public BZip2Format()
        : base("BZIP2", new[] { ".bz2", ".bzip2" }, "bzip2 single-file compression (native core)", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => WrapWithNative("bzip2", source, decompress: true);

    internal override Stream OpenCompress(Stream destination) => WrapWithNative("bzip2", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 3 && prefix[0] == (byte)'B' && prefix[1] == (byte)'Z' && prefix[2] == (byte)'h';

    internal override string? NativeCodecId => "bzip2";

    /// <summary>供 TAR.BZ2 包装：解压为临时解码流；压缩为缓冲编码流（Dispose 时落盘）。</summary>
    internal static Stream WrapWithNative(string codec, Stream stream, bool decompress)
    {
        NativeCodecRouter.EnsureCore();
        return decompress
            ? new NativeTempDecodeStream(stream, codec)
            : new NativeTempEncodeStream(stream, codec);
    }
}

/// <summary>
/// xz 单文件格式（.xz）。编解码经 Rust 原生核心（LZMA2）；核心缺失时不可用。
/// </summary>
public sealed class XzFormat : SingleFileCodecFormat
{
    public XzFormat()
        : base("XZ", new[] { ".xz" }, "xz (LZMA2) single-file compression (native core)", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => BZip2Format.WrapWithNative("xz", source, decompress: true);

    internal override Stream OpenCompress(Stream destination) => BZip2Format.WrapWithNative("xz", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 6 && prefix[0] == 0xFD && prefix[1] == 0x37 && prefix[2] == 0x7A
           && prefix[3] == 0x58 && prefix[4] == 0x5A && prefix[5] == 0x00;

    internal override string? NativeCodecId => "xz";
}

/// <summary>
/// Zstandard 单文件格式（.zst）。编解码经 Rust 原生核心（纯 Rust 实现）；核心缺失时不可用。
/// </summary>
public sealed class ZstdFormat : SingleFileCodecFormat
{
    public ZstdFormat()
        : base("ZSTD", new[] { ".zst", ".zstd" }, "Zstandard single-file compression (native core)", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => BZip2Format.WrapWithNative("zstd", source, decompress: true);

    internal override Stream OpenCompress(Stream destination) => BZip2Format.WrapWithNative("zstd", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 4 && prefix[0] == 0x28 && prefix[1] == 0xB5 && prefix[2] == 0x2F && prefix[3] == 0xFD;

    internal override string? NativeCodecId => "zstd";
}

/// <summary>
/// LZ4 帧格式（.lz4）。编解码经 Rust 原生核心（lz4_flex 纯 Rust 实现）；核心缺失时不可用。
/// </summary>
public sealed class Lz4Format : SingleFileCodecFormat
{
    public Lz4Format()
        : base("LZ4", new[] { ".lz4" }, "LZ4 frame single-file compression (native core)", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => BZip2Format.WrapWithNative("lz4", source, decompress: true);

    internal override Stream OpenCompress(Stream destination) => BZip2Format.WrapWithNative("lz4", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length)
        => length >= 4 && prefix[0] == 0x04 && prefix[1] == 0x22 && prefix[2] == 0x4D && prefix[3] == 0x18;

    internal override string? NativeCodecId => "lz4";
}

/// <summary>
/// Brotli 单文件格式（.br）。编解码经 Rust 原生核心（brotli 纯 Rust 实现）；核心缺失时不可用。
/// Brotli 无魔数（流首即位流），仅支持扩展名识别。
/// </summary>
public sealed class BrotliFormat : SingleFileCodecFormat
{
    public BrotliFormat()
        : base("BROTLI", new[] { ".br" }, "Brotli single-file compression (native core)", supportsWrite: true)
    {
    }

    protected override Stream OpenDecompress(Stream source) => BZip2Format.WrapWithNative("brotli", source, decompress: true);

    internal override Stream OpenCompress(Stream destination) => BZip2Format.WrapWithNative("brotli", destination, decompress: false);

    protected override bool MatchesPrefix(byte[] prefix, int length) => false; // 无魔数：仅扩展名识别

    internal override string? NativeCodecId => "brotli";
}
