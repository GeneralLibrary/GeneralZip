using System;
using System.IO;
using System.Runtime.InteropServices;

namespace GeneralZip.Internal;

internal sealed class PrivateTempDirectory : IDisposable
{
    public PrivateTempDirectory(string prefix)
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"{prefix}-{Guid.NewGuid():N}");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Directory.CreateDirectory(Path);
        }
        else if (Mkdir(Path, Convert.ToUInt32("700", 8)) != 0)
        {
            throw new IOException($"Could not create private temporary directory (errno {Marshal.GetLastWin32Error()})");
        }
    }

    public string Path { get; }

    public string FilePath(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch { }
    }

    [DllImport("libc", EntryPoint = "mkdir", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int Mkdir(string path, uint mode);
}
