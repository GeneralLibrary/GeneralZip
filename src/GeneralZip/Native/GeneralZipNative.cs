using System;
using GeneralZip;
using GeneralZip.Formats.Codecs;

namespace GeneralZip.Native;

/// <summary>
/// GeneralZip 原生能力入口：原生引导已隐式完成——首次访问任何 API 时，
/// <see cref="GeneralZipFormatRegistry"/> 的装配会自动加载核心并注册
/// 7z/RAR 提供者与原生编解码桥接（幂等；7z/RAR/bz2/xz/zstd/lz4），无需手动调用。
/// 原生核心缺失时安全降级：7z/RAR 不注册、原生编解码格式报明确异常；纯托管能力不受影响。
/// </summary>
public static class GeneralZipNative
{
    /// <summary>
    /// 原生引导（幂等）：加载原生核心；成功时向 <paramref name="registry"/> 注册 7z/RAR
    /// （registry 为 null 则跳过注册）并注入编解码桥接委托，失败静默降级。
    /// 不访问 <see cref="GeneralZipFormatRegistry"/>——由调用方传入实例，
    /// 避免静态构造器重入拿到半初始化的注册表。
    /// </summary>
    internal static void Bootstrap(GeneralZipFormatRegistry? registry)
    {
        if (!NativeCoreLoader.TryLoad())
        {
            return;
        }

        var caps = NativeCoreLoader.Capabilities;

        // 7z 能力（sevenz-rust2，纯 Rust）
        if (registry != null && (caps & NativeCoreLoader.CapabilitySevenZ) != 0)
        {
            registry.Register(new SevenZipNativeFormat());
        }

        // RAR 能力（unrar 封装，需 C++ 工具链构建的原生核心）
        if (registry != null && (caps & NativeCoreLoader.CapabilityRar) != 0)
        {
            registry.Register(new RarNativeFormat());
        }

        // 单文件编解码桥接（bzip2 / xz / zstd / lz4）：核心经 NativeBridge 间接调用
        NativeBridge.IsAvailable = () => NativeCoreLoader.IsAvailable;
        NativeBridge.Compress = (codec, src, dst) =>
            InvokeCodec(codec, src, dst, compress: true, caps);
        NativeBridge.Decompress = (codec, src, dst) =>
            InvokeCodec(codec, src, dst, compress: false, caps);
    }

    /// <summary>确保编解码桥接已注入（自定义注册表场景的兜底，幂等）。</summary>
    internal static void EnsureBridge() => Bootstrap(null);

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
