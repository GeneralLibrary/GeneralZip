using System;
using GeneralZip;
using GeneralZip.Formats.Codecs;

namespace GeneralZip.Native;

/// <summary>
/// GeneralZip 原生能力入口：一行注册 7z/RAR 提供者与原生编解码桥接。
/// <code>
/// GeneralZip.Initialize();          // 核心引导（幂等）
/// GeneralZipNative.Initialize();    // 原生引导（可选；7z/RAR/bz2/xz/zstd/lz4）
/// </code>
/// 原生核心缺失时安全降级：7z/RAR 不注册、原生编解码格式报明确异常；纯托管能力不受影响。
/// </summary>
public static class GeneralZipNative
{
    private static readonly object Lock = new();
    private static bool _initialized;

    /// <summary>加载原生核心并注册能力（幂等、线程安全）。返回核心是否可用。</summary>
    public static bool Initialize()
    {
        lock (Lock)
        {
            if (_initialized)
            {
                return NativeCoreLoader.IsAvailable;
            }

            _initialized = true;

            if (!NativeCoreLoader.TryLoad())
            {
                return false;
            }

            var registry = ArchiveFormatRegistry.Default;

            // 7z 能力（sevenz-rust2，纯 Rust）
            if ((NativeCoreLoader.Capabilities & NativeCoreLoader.CapabilitySevenZ) != 0)
            {
                registry.Register(new SevenZipNativeFormat());
            }

            // RAR 能力（unrar 封装，需 C++ 工具链构建的原生核心）
            if ((NativeCoreLoader.Capabilities & NativeCoreLoader.CapabilityRar) != 0)
            {
                registry.Register(new RarNativeFormat());
            }

            // 单文件编解码桥接（bzip2 / xz / zstd / lz4）：核心包经 NativeBridge 间接调用
            var caps = NativeCoreLoader.Capabilities;
            NativeBridge.IsAvailable = () => NativeCoreLoader.IsAvailable;
            NativeBridge.Compress = (codec, src, dst) =>
                InvokeCodec(codec, src, dst, compress: true, caps);
            NativeBridge.Decompress = (codec, src, dst) =>
                InvokeCodec(codec, src, dst, compress: false, caps);

            return true;
        }
    }

    private static bool InvokeCodec(string codec, string src, string dst, bool compress, uint caps)
    {
        // bzip2/xz/lz4/zstd 全部挂在 XZ 能力位之下（同一批纯 Rust 编解码器）
        if ((caps & NativeCoreLoader.CapabilityXz) == 0)
        {
            return false;
        }

        var status = compress
            ? GzpNative.gzp_codec_compress(codec, src, dst)
            : GzpNative.gzp_codec_decompress(codec, src, dst);

        if (status == GzpNative.GzpOk)
        {
            return true;
        }

        throw NativeCall.ToException(status, $"Native codec failed ({codec}, {(compress ? "compress" : "decompress")})");
    }

    /// <summary>原生核心版本号（未加载为 null）。</summary>
    public static string? CoreVersion
    {
        get
        {
            if (!NativeCoreLoader.TryLoad())
            {
                return null;
            }

            var ptr = GzpNative.gzp_version();
            if (ptr == IntPtr.Zero)
            {
                return null;
            }

#if NET8_0_OR_GREATER
            return System.Runtime.InteropServices.Marshal.PtrToStringUTF8(ptr);
#else
            var len = 0;
            while (System.Runtime.InteropServices.Marshal.ReadByte(ptr, len) != 0)
            {
                len++;
            }

            var bytes = new byte[len];
            System.Runtime.InteropServices.Marshal.Copy(ptr, bytes, 0, len);
            return System.Text.Encoding.UTF8.GetString(bytes);
#endif
        }
    }

    /// <summary>原生核心加载路径（未加载为 null）。</summary>
    public static string? CorePath => NativeCoreLoader.LoadedPath;
}
