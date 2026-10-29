using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// 组件启动引导与门面入口（与组件同名）。
/// <para>
/// <see cref="Initialize"/> 完成内置格式/加密算法注册（幂等，可重复调用）；
/// 随后即可使用一行式 API（<see cref="CompressAsync"/>/<see cref="ExtractAsync"/> 等），
/// 需要事件与精细控制时使用 <see cref="ArchiveReader"/> / <see cref="ArchiveWriter"/>。
/// </para>
/// <code>
/// GeneralZip.Initialize();
/// await GeneralZip.CompressAsync(@"C:\data", @"D:\out.zip",
///     o => { o.EncryptionAlgorithm = "SM4-GM"; o.Password = "p@ss"; });
/// </code>
/// </summary>
public static class GeneralZip
{
    private static int _initialized;

    /// <summary>
    /// 启动引导：确保内置格式提供者与加密算法已注册（幂等、线程安全）。
    /// Default 注册表本就随首次访问自动装配，此调用用于显式化的启动时机与后续扩展点。
    /// </summary>
    public static void Initialize()
    {
        if (Interlocked.Exchange(ref _initialized, 1) == 1)
        {
            return;
        }

        // 触发两个默认注册表的静态装配
        _ = ArchiveFormatRegistry.Default;
        _ = EncryptionRegistry.Default;
    }

    /// <summary>组件版本。</summary>
    public static Version Version => typeof(GeneralZip).Assembly.GetName().Version ?? new Version(0, 0, 0);

    /// <summary>默认格式注册表（可注册自定义格式与原生 7z/RAR 提供者）。</summary>
    public static ArchiveFormatRegistry Registry => ArchiveFormatRegistry.Default;

    /// <summary>默认加密算法注册表（ZipCrypto / WinZip AES / SM4-GM 已内置）。</summary>
    public static EncryptionRegistry Encryption => EncryptionRegistry.Default;

    /// <summary>探测归档格式：魔数优先，扩展名兜底。无法识别返回 null。</summary>
    public static ArchiveFormatInfo? DetectFormat(string path)
    {
        if (path == null) throw new ArgumentNullException(nameof(path));
        var reg = ArchiveFormatRegistry.Default;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        return (reg.Detect(stream) ?? reg.DetectByExtension(path))?.Info;
    }

    /// <summary>从流前部探测格式（流 Position 保持不变，若可寻址）。</summary>
    public static ArchiveFormatInfo? DetectFormat(Stream stream)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        var reg = ArchiveFormatRegistry.Default;
        long pos = 0;
        if (stream.CanSeek)
        {
            pos = stream.Position;
        }

        var format = reg.Detect(stream.CanSeek ? stream : new ReadAheadProbeStream(stream));
        if (stream.CanSeek)
        {
            stream.Position = pos;
        }

        return format?.Info;
    }

    /// <summary>压缩文件或目录到归档（扩展名决定格式）。</summary>
    public static void Compress(
        string sourcePath,
        string archivePath,
        Action<ArchiveWriteOptions>? configure = null,
        CancellationToken cancellationToken = default)
        => CompressAsync(sourcePath, archivePath, configure, cancellationToken).GetAwaiter().GetResult();

    /// <summary>压缩文件或目录到归档。</summary>
    public static async Task CompressAsync(
        string sourcePath,
        string archivePath,
        Action<ArchiveWriteOptions>? configure = null,
        CancellationToken cancellationToken = default)
    {
        if (sourcePath == null) throw new ArgumentNullException(nameof(sourcePath));

        using var writer = ArchiveWriter.CreateNew(archivePath, configure);

        if (File.Exists(sourcePath))
        {
            await writer.AddFileAsync(sourcePath, null, cancellationToken).ConfigureAwait(false);
        }
        else if (Directory.Exists(sourcePath))
        {
            var name = new DirectoryInfo(sourcePath).Name;
            var hasChildren = Directory.EnumerateFileSystemEntries(sourcePath).GetEnumerator().MoveNext();
            await writer.AddDirectoryAsync(
                sourcePath,
                entryPrefix: hasChildren ? name : null,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        else
        {
            throw new FileNotFoundException("Source path does not exist", sourcePath);
        }

        await writer.FinishAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>解压归档到目录。</summary>
    public static ArchiveResult Extract(
        string archivePath,
        string destinationDirectory,
        Action<ArchiveOpenOptions>? configure = null,
        ExtractionOptions? extraction = null,
        CancellationToken cancellationToken = default)
        => ExtractAsync(archivePath, destinationDirectory, configure, extraction, cancellationToken).GetAwaiter().GetResult();

    /// <summary>解压归档到目录。</summary>
    public static async Task<ArchiveResult> ExtractAsync(
        string archivePath,
        string destinationDirectory,
        Action<ArchiveOpenOptions>? configure = null,
        ExtractionOptions? extraction = null,
        CancellationToken cancellationToken = default)
    {
        using var reader = await ArchiveReader.OpenAsync(archivePath, configure, null, null, cancellationToken).ConfigureAwait(false);
        return reader.ExtractToDirectory(destinationDirectory, extraction, cancellationToken);
    }

    /// <summary>完整性测试（校验 CRC/HMAC/结构，不落盘）。</summary>
    public static ArchiveResult Test(
        string archivePath,
        Action<ArchiveOpenOptions>? configure = null,
        CancellationToken cancellationToken = default)
    {
        using var reader = ArchiveReader.Open(archivePath, configure);
        return reader.TestAll(new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll }, cancellationToken);
    }
}
