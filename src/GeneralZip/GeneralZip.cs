using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// 静态门面入口（与组件同名，零初始化：内置格式/加密算法与原生能力均在首次使用时隐式装配）。
/// <para>
/// 直接使用一行式 API（<see cref="CompressAsync"/>/<see cref="ExtractAsync"/> 等），
/// 需要事件与精细控制时使用 <see cref="GeneralZipReader"/> / <see cref="GeneralZipWriter"/>。
/// </para>
/// <code>
/// await GeneralZip.CompressAsync(@"C:\data", @"D:\out.zip",
///     o => { o.EncryptionAlgorithm = "SM4-GM"; o.Password = "p@ss"; });
/// </code>
/// </summary>
public static class GeneralZip
{
    /// <summary>组件版本。</summary>
    public static Version Version => typeof(GeneralZip).Assembly.GetName().Version ?? new Version(0, 0, 0);

    /// <summary>默认格式注册表（可注册自定义格式与原生 7z/RAR 提供者）。</summary>
    public static GeneralZipFormatRegistry Registry => GeneralZipFormatRegistry.Default;

    /// <summary>默认加密算法注册表（ZipCrypto / WinZip AES / SM4-GM 已内置）。</summary>
    public static GeneralZipEncryptionRegistry Encryption => GeneralZipEncryptionRegistry.Default;

    /// <summary>探测归档格式：魔数优先，扩展名兜底；*.NNN 分卷按拼接流探测。无法识别返回 null。</summary>
    public static ArchiveFormatInfo? DetectFormat(string path)
    {
        if (path == null) throw new ArgumentNullException(nameof(path));
        var reg = GeneralZipFormatRegistry.Default;

        var volumes = global::GeneralZip.Internal.SplitVolumeLocator.Resolve(path);
        if (volumes != null)
        {
            using var volumeStream = new global::GeneralZip.Internal.MultiVolumeStream(volumes);
            return (reg.Detect(volumeStream) ?? reg.DetectByExtension(volumes[0]))?.Info;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        return (reg.Detect(stream) ?? reg.DetectByExtension(path))?.Info;
    }

    /// <summary>从流前部探测格式（流 Position 保持不变，若可寻址）。</summary>
    public static ArchiveFormatInfo? DetectFormat(Stream stream)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        var reg = GeneralZipFormatRegistry.Default;
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

        using var writer = GeneralZipWriter.CreateNew(archivePath, configure);

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
        using var reader = await GeneralZipReader.OpenAsync(archivePath, configure, null, null, cancellationToken).ConfigureAwait(false);
        return reader.ExtractToDirectory(destinationDirectory, extraction, cancellationToken);
    }

    /// <summary>完整性测试（校验 CRC/HMAC/结构，不落盘）。</summary>
    public static ArchiveResult Test(
        string archivePath,
        Action<ArchiveOpenOptions>? configure = null,
        CancellationToken cancellationToken = default)
    {
        using var reader = GeneralZipReader.Open(archivePath, configure);
        return reader.TestAll(new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll }, cancellationToken);
    }

    // ---------- 流式门面（Stream → Stream，不落盘） ----------

    /// <summary>把源流压缩为归档流（单条目）。格式由 formatName 显式指定（流无法从扩展名推断）。</summary>
    /// <param name="source">明文源流（读取到 EOF）。</param>
    /// <param name="output">归档输出流（保持打开，由调用方处置）。</param>
    /// <param name="formatName">格式名（如 "ZIP"、"GZIP"）。</param>
    /// <param name="entryName">条目名；null 为 "content"。</param>
    public static void Compress(
        Stream source,
        Stream output,
        string formatName,
        string? entryName = null,
        Action<ArchiveWriteOptions>? configure = null,
        CancellationToken cancellationToken = default)
        => CompressAsync(source, output, formatName, entryName, configure, cancellationToken).GetAwaiter().GetResult();

    /// <summary>异步把源流压缩为归档流（单条目）。</summary>
    public static async Task CompressAsync(
        Stream source,
        Stream output,
        string formatName,
        string? entryName = null,
        Action<ArchiveWriteOptions>? configure = null,
        CancellationToken cancellationToken = default)
    {
        if (source == null) throw new ArgumentNullException(nameof(source));
        if (output == null) throw new ArgumentNullException(nameof(output));
        if (formatName == null) throw new ArgumentNullException(nameof(formatName));

        using (var writer = GeneralZipWriter.CreateNew(output, formatName, configure))
        {
            if (source.CanSeek)
            {
                var remaining = source.Length - source.Position;
                if (remaining < 0) throw new IOException("Stream position is beyond its length");
                await writer.AddStreamAsync(entryName ?? "content", source, remaining, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                using var tempDirectory = new Internal.PrivateTempDirectory("gzp-stream");
                var tempPath = tempDirectory.FilePath("input.bin");
                using (var buffered = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    await source.CopyToAsync(buffered, 81920, cancellationToken).ConfigureAwait(false);
                }

                using var bufferedInput = File.OpenRead(tempPath);
                await writer.AddStreamAsync(entryName ?? "content", bufferedInput, bufferedInput.Length, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
            }

            await writer.FinishAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>从归档流解压到目录（魔数自动探测格式，扩展名兜底）。</summary>
    public static ArchiveResult Extract(
        Stream input,
        string destinationDirectory,
        string? formatName = null,
        Action<ArchiveOpenOptions>? configure = null,
        ExtractionOptions? extraction = null,
        CancellationToken cancellationToken = default)
        => ExtractAsync(input, destinationDirectory, formatName, configure, extraction, cancellationToken).GetAwaiter().GetResult();

    /// <summary>异步从归档流解压到目录。</summary>
    public static async Task<ArchiveResult> ExtractAsync(
        Stream input,
        string destinationDirectory,
        string? formatName = null,
        Action<ArchiveOpenOptions>? configure = null,
        ExtractionOptions? extraction = null,
        CancellationToken cancellationToken = default)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));
        if (destinationDirectory == null) throw new ArgumentNullException(nameof(destinationDirectory));

        using var reader = GeneralZipReader.Open(input, formatName, configure);
        return await Task.Run(
            () => reader.ExtractToDirectory(destinationDirectory, extraction, cancellationToken),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>完整性测试（归档流版）。</summary>
    public static ArchiveResult Test(
        Stream input,
        string? formatName = null,
        Action<ArchiveOpenOptions>? configure = null,
        CancellationToken cancellationToken = default)
    {
        using var reader = GeneralZipReader.Open(input, formatName, configure);
        return reader.TestAll(new ExtractionOptions { ErrorPolicy = ErrorPolicy.SkipAll }, cancellationToken);
    }

    // ---------- 追加 / 删除 / 转换（读出→重写语义） ----------

    /// <summary>
    /// 向既有归档追加文件或目录（读出→重写语义：源归档条目被忠实复制，新内容按选项追加）。
    /// <para>源归档加密时须用 <paramref name="configure"/> 提供口令（同时用于读取与重新加密）；
    /// 原条目被重新加密，原加密参数（盐/IV）不保留。RAR 等只读格式不支持。</para>
    /// </summary>
    public static void Append(
        string archivePath,
        string sourcePath,
        Action<ArchiveWriteOptions>? configure = null,
        CancellationToken cancellationToken = default)
        => AppendAsync(archivePath, sourcePath, configure, cancellationToken).GetAwaiter().GetResult();

    /// <summary>异步向既有归档追加文件或目录。</summary>
    public static Task AppendAsync(
        string archivePath,
        string sourcePath,
        Action<ArchiveWriteOptions>? configure = null,
        CancellationToken cancellationToken = default)
        => RewriteArchiveCore(
            archivePath,
            openConfigure: PasswordFromWriteOptions(configure),
            populate: writer => Repack.AddSourcePath(writer, sourcePath, cancellationToken),
            keepEntry: null,
            writeConfigure: configure,
            replaceOriginal: true,
            cancellationToken,
            inheritEncryption: true);

    /// <summary>
    /// 从归档删除条目（读出→重写语义）。按精确条目名（<paramref name="entryNames"/>，OrdinalIgnoreCase）
    /// 或谓词（<paramref name="predicate"/>）匹配；两者可同时提供（并集）。
    /// </summary>
    public static void Remove(
        string archivePath,
        IEnumerable<string>? entryNames = null,
        Func<IArchiveEntry, bool>? predicate = null,
        Action<ArchiveOpenOptions>? configure = null,
        CancellationToken cancellationToken = default)
        => RemoveAsync(archivePath, entryNames, predicate, configure, cancellationToken).GetAwaiter().GetResult();

    /// <summary>异步从归档删除条目。</summary>
    public static Task RemoveAsync(
        string archivePath,
        IEnumerable<string>? entryNames = null,
        Func<IArchiveEntry, bool>? predicate = null,
        Action<ArchiveOpenOptions>? configure = null,
        CancellationToken cancellationToken = default)
    {
        var nameSet = entryNames != null
            ? new HashSet<string>(entryNames, StringComparer.OrdinalIgnoreCase)
            : null;
        if (nameSet == null && predicate == null)
        {
            throw new ArgumentException("Provide entryNames or predicate", nameof(entryNames));
        }

        return RewriteArchiveCore(
            archivePath,
            configure,
            populate: null,
            keepEntry: entry =>
                (nameSet != null && nameSet.Contains(entry.FullName))
                || (predicate != null && predicate(entry))
                    ? false
                    : true,
            writeConfigure: null,
            replaceOriginal: true,
            cancellationToken,
            inheritEncryption: true);
    }

    /// <summary>
    /// 跨格式转换归档（读出→重写：全部条目复制进目标格式，目标格式由目标路径扩展名决定）。
    /// 加密不跨格式保留；需重新加密时用 <paramref name="writeConfigure"/> 指定算法与口令。
    /// </summary>
    public static void Convert(
        string sourceArchive,
        string targetArchive,
        Action<ArchiveWriteOptions>? writeConfigure = null,
        Action<ArchiveOpenOptions>? openConfigure = null,
        CancellationToken cancellationToken = default)
        => ConvertAsync(sourceArchive, targetArchive, writeConfigure, openConfigure, cancellationToken).GetAwaiter().GetResult();

    /// <summary>异步跨格式转换归档。</summary>
    public static Task ConvertAsync(
        string sourceArchive,
        string targetArchive,
        Action<ArchiveWriteOptions>? writeConfigure = null,
        Action<ArchiveOpenOptions>? openConfigure = null,
        CancellationToken cancellationToken = default)
        => RewriteArchiveCore(
            sourceArchive,
            openConfigure,
            populate: null,
            keepEntry: null,
            writeConfigure,
            replaceOriginal: false,
            cancellationToken,
            targetArchive: targetArchive);

    private static Action<ArchiveOpenOptions>? PasswordFromWriteOptions(Action<ArchiveWriteOptions>? configure)
    {
        if (configure == null)
        {
            return null;
        }

        var probe = new ArchiveWriteOptions();
        configure(probe);
        if (probe.Password == null)
        {
            return null;
        }

        return o => o.Password = probe.Password;
    }

    /// <summary>重写核心：读源归档 → 复制条目 → populate 追加 → Finish →（可选）替换原文件。</summary>
    private static async Task RewriteArchiveCore(
        string sourceArchive,
        Action<ArchiveOpenOptions>? openConfigure,
        Action<GeneralZipWriter>? populate,
        Func<IArchiveEntry, bool>? keepEntry,
        Action<ArchiveWriteOptions>? writeConfigure,
        bool replaceOriginal,
        CancellationToken cancellationToken,
        string? targetArchive = null,
        bool inheritEncryption = false)
    {
        if (sourceArchive == null) throw new ArgumentNullException(nameof(sourceArchive));

        var target = replaceOriginal ? sourceArchive : targetArchive
                     ?? throw new ArgumentNullException(nameof(targetArchive));
        if (replaceOriginal && Internal.VolumeSplitStream.IsFirstVolumePath(sourceArchive))
        {
            throw new NotSupportedException("Append and Remove do not support in-place rewriting of split ZIP archives");
        }

        string? configuredReadPassword = null;
        Action<ArchiveOpenOptions>? observedOpenConfigure = openConfigure == null
            ? null
            : options =>
            {
                openConfigure(options);
                configuredReadPassword = options.Password;
            };
        using var reader = GeneralZipReader.Open(sourceArchive, observedOpenConfigure);
        // 追加/删除保持源格式；转换（replaceOriginal=false）由目标路径扩展名推断目标格式
        var formatName = replaceOriginal ? reader.Format.Name : null;

        // 追加加密归档的安全默认：给了口令但未指定算法时，继承源归档的加密算法，
        // 避免"口令仅用于读取、产物静默变成明文"的坑。
        string? inheritedAlgorithm = null;
        string? inheritedPassword = null;
        if (inheritEncryption)
        {
            var probe = new ArchiveWriteOptions();
            writeConfigure?.Invoke(probe);
            if (probe.EncryptionAlgorithm == null && probe.EncryptionProvider == null)
            {
                var algorithms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var e in reader.Entries)
                {
                    if (!e.IsDirectory && e.IsEncrypted && e.EncryptionAlgorithm != null)
                    {
                        algorithms.Add(e.EncryptionAlgorithm);
                    }
                }

                if (algorithms.Count > 1)
                    throw new NotSupportedException("Cannot safely rewrite an archive containing multiple encryption algorithms");
                inheritedAlgorithm = algorithms.SingleOrDefault();
                inheritedPassword = probe.Password ?? configuredReadPassword;
                if (inheritedAlgorithm != null && inheritedPassword == null)
                    throw new InvalidOperationException("Rewriting encrypted archives requires a password for re-encryption");
            }
        }

        // 临时文件保留源名后缀（复合扩展名 ".tar.gz" 可被 DetectByExtension 正确推断）
        var finalPath = Path.GetFullPath(target);
        var tempPath = Repack.TempSiblingPath(finalPath);
        try
        {
            using (var writer = GeneralZipWriter.CreateNew(tempPath, o =>
                   {
                       writeConfigure?.Invoke(o);
                       if (inheritedAlgorithm != null && o.EncryptionAlgorithm == null && o.EncryptionProvider == null)
                       {
                           o.EncryptionAlgorithm = inheritedAlgorithm;
                           o.Password ??= inheritedPassword;
                           if (string.Equals(inheritedAlgorithm, "SM2-GM", StringComparison.OrdinalIgnoreCase)
                               && o.RecipientPublicKey == null && o.Password != null)
                           {
                               o.RecipientPublicKey = Cryptography.Sm2KeyPair.FromPrivateKeyHex(o.Password).PublicKeyHex;
                           }
                       }
                   }, formatName))
            {
                Repack.CopyEntries(reader, writer, keepEntry, cancellationToken);
                populate?.Invoke(writer);
                await writer.FinishAsync(cancellationToken).ConfigureAwait(false);
            }

            // 覆盖原文件前先关闭源归档句柄（FileShare.Read 下 Move-overwrite 会失败）
            reader.Dispose();
            Repack.MoveOverwrite(tempPath, finalPath);
        }
        finally
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { /* 清理失败忽略 */ }
        }
    }
}
