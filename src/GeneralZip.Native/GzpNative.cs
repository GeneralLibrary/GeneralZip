using System;
using System.Runtime.InteropServices;
using System.Text;

namespace GeneralZip.Native;

/// <summary>原生核心导出函数绑定。</summary>
internal static class GzpNative
{
    public const string LibName = "generalzip_native";

    public const int GzpOk = 0;
    public const int GzpErrIo = -1;
    public const int GzpErrFormat = -2;
    public const int GzpErrPassword = -3;
    public const int GzpErrNotFound = -4;
    public const int GzpErrUnsupported = -5;
    public const int GzpErrPanic = -6;
    public const int GzpErrArg = -7;
    public const int GzpErrBuffer = -8;

    public delegate void ProgressCallback(nuint done, nuint total, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void ProgressCallbackStd(nuint done, nuint total, IntPtr userData);

    // ---------- 基础 ----------

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern IntPtr gzp_version();

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern uint gzp_capabilities();

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern void gzp_free(IntPtr ptr);

    public static string LastError()
    {
        var buf = new byte[1024];
        int len;
        do
        {
            len = gzp_last_error(buf, (uint)buf.Length);
        }
        while (false);

        return len > 0 ? Encoding.UTF8.GetString(buf, 0, len) : "未知原生错误";
    }

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_last_error(byte[] buffer, uint capacity);

    // ---------- 7z ----------

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_7z_list_json(
        string path, byte[]? password, uint passwordLength, byte[]? output, uint capacity, out uint needed);

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_7z_extract(
        string path, byte[]? password, uint passwordLength, long index, string destDir,
        [MarshalAs(UnmanagedType.FunctionPtr)] ProgressCallbackStd? progress, IntPtr userData);

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_7z_compress(
        string sourcesJson, string dest, byte[]? password, uint passwordLength,
        [MarshalAs(UnmanagedType.FunctionPtr)] ProgressCallbackStd? progress, IntPtr userData);

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_7z_test(
        string path, byte[]? password, uint passwordLength,
        [MarshalAs(UnmanagedType.FunctionPtr)] ProgressCallbackStd? progress, IntPtr userData);

    // ---------- RAR（核心具备 rar 能力时可用） ----------

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_rar_list_json(
        string path, byte[]? password, uint passwordLength, byte[]? output, uint capacity, out uint needed);

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_rar_extract(
        string path, byte[]? password, uint passwordLength, long index, string destDir,
        [MarshalAs(UnmanagedType.FunctionPtr)] ProgressCallbackStd? progress, IntPtr userData);

    // ---------- 单文件编解码（bzip2 / lz4 / zstd；xz 见下方专用入口） ----------

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_codec_compress(string codec, string src, string dst);

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_codec_decompress(string codec, string src, string dst);

    // ---------- xz ----------

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_xz_compress(string src, string dst);

    [DllImport(LibName, CallingConvention = CallingConvention.Winapi)]
    public static extern int gzp_xz_decompress(string src, string dst);

    // ---------- 工具 ----------

    public static byte[]? PasswordBytes(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return null;
        }

        var bytes = Encoding.UTF8.GetBytes(password);
        Array.Resize(ref bytes, bytes.Length + 1); // 结尾 NUL 仅为安全余量（长度显式传递）
        return bytes;
    }
}
