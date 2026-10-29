using System;
using System.IO;
using System.Runtime.InteropServices;

namespace GeneralZip.Native;

/// <summary>
/// 原生核心加载器：按候选路径探测并预加载 cdylib。
/// 加载成功后 P/Invoke 按模块名解析到已加载实例；加载失败时本包提供者不注册，
/// 访问 7z/RAR 抛 <see cref="NativeCoreMissingException"/>（含部署指引）。
/// </summary>
public static class NativeCoreLoader
{
    public const uint CapabilitySevenZ = 1;
    public const uint CapabilityRar = 2;
    public const uint CapabilityXz = 4;

    private static readonly object Lock = new();
    private static bool _initialized;
    private static bool _loaded;
    private static uint _capabilities;
    private static string? _loadedPath;
    private static string? _failureReason;

    /// <summary>原生库实际加载路径（未加载为 null）。</summary>
    public static string? LoadedPath => Volatile.Read(ref _loadedPath);

    /// <summary>原生能力位（未加载为 0）。</summary>
    public static uint Capabilities => Volatile.Read(ref _capabilities);

    public static bool IsAvailable => Volatile.Read(ref _loaded);

    /// <summary>探测并加载原生核心（幂等、线程安全）。</summary>
    public static bool TryLoad()
    {
        if (Volatile.Read(ref _initialized))
        {
            return Volatile.Read(ref _loaded);
        }

        lock (Lock)
        {
            if (_initialized)
            {
                return _loaded;
            }

            var (found, reason) = Probe();
            _failureReason = reason;

            if (found != null)
            {
                try
                {
                    if (LoadLibrary(found))
                    {
                        _loadedPath = found;
                        _capabilities = GzpNative.gzp_capabilities();
                        _loaded = true;
                    }
                }
                catch (Exception ex)
                {
                    _failureReason = $"Load failed for {found}: {ex.Message}";
                }
            }

            _initialized = true;
            return _loaded;
        }
    }

    /// <summary>确保已加载，否则抛出带指引的异常。</summary>
    public static void EnsureLoaded()
    {
        if (!TryLoad())
        {
            throw new NativeCoreMissingException(
                "The GeneralZip native core (generalzip_native) is not loaded; 7z/RAR capabilities are unavailable.\n" +
                $"Probe details: {_failureReason}\n" +
                "Deployment options (any one of):\n" +
                "  1) Place generalzip_native.dll/.so/.dylib for your RID in the application directory;\n" +
                "  2) Place it under <app dir>/runtimes/<RID>/native/ (win-x64/win-x86/linux-x64/osx-arm64);\n" +
                "  3) Set the GENERALZIP_NATIVE environment variable to the library path;\n" +
                "  4) Build it yourself: run cargo build --release in native/generalzip-native of the repository.");
        }
    }

    public static string? FailureReason => _failureReason;

    // ---------- 实现 ----------

    private static (string? found, string reason) Probe()
    {
        var candidates = new System.Collections.Generic.List<string>();
        var baseDir = AppContext.BaseDirectory;

        var env = Environment.GetEnvironmentVariable("GENERALZIP_NATIVE");
        if (!string.IsNullOrWhiteSpace(env))
        {
            candidates.Add(env);
        }

        string? rid = null;
#if NET8_0_OR_GREATER
        rid = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.X64 => OperatingSystem.IsWindows() ? "win-x64"
                : OperatingSystem.IsLinux() ? "linux-x64" : "osx-x64",
            System.Runtime.InteropServices.Architecture.X86 => "win-x86",
            System.Runtime.InteropServices.Architecture.Arm64 => OperatingSystem.IsWindows() ? "win-arm64"
                : OperatingSystem.IsLinux() ? "linux-arm64" : "osx-arm64",
            _ => null,
        };
#else
        rid = Environment.Is64BitProcess
            ? (IsWindows() ? "win-x64" : IsOSX() ? "osx-x64" : "linux-x64")
            : "win-x86";
#endif

        if (rid != null)
        {
            candidates.Add(Path.Combine(baseDir, "runtimes", rid, "native", LibraryFileName));
        }

        candidates.Add(Path.Combine(baseDir, LibraryFileName));

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return (candidate, "found");
            }
        }

        return (null, $"{LibraryFileName} was not found in any of these paths: {string.Join("; ", candidates)}");
    }

    internal static string LibraryFileName =>
        IsWindows() ? "generalzip_native.dll" : IsOSX() ? "libgeneralzip_native.dylib" : "libgeneralzip_native.so";

    private static bool LoadLibrary(string path)
    {
#if NET8_0_OR_GREATER
        return System.Runtime.InteropServices.NativeLibrary.TryLoad(path, out _);
#else
        if (IsWindows())
        {
            return WindowsLoadLibrary(path) != IntPtr.Zero;
        }

        // netstandard2.0 非 Windows 场景有限支持：依赖默认搜索顺序
        return true;
#endif
    }

#if !NET8_0_OR_GREATER
    private static bool IsWindows() =>
        System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows);

    private static bool IsOSX() =>
        System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX);

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr WindowsLoadLibrary(string lpLibFileName);
#else
    internal static bool IsWindows() => OperatingSystem.IsWindows();
    private static bool IsOSX() => OperatingSystem.IsMacOS();
#endif
}
