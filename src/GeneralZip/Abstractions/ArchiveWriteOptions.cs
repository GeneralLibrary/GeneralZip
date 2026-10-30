using System;
using System.IO;
using System.Text;

namespace GeneralZip.Abstractions;

/// <summary>压缩级别。与 <see cref="System.IO.Compression.CompressionLevel"/> 语义对齐。</summary>
public enum CompressionLevelChoice
{
    NoCompression = 0,
    Fastest = 1,
    Optimal = 2,
    SmallestSize = 3,
}

/// <summary>创建归档的选项。</summary>
public sealed class ArchiveWriteOptions
{
    /// <summary>压缩级别。默认 Optimal。</summary>
    public CompressionLevelChoice Level { get; set; } = CompressionLevelChoice.Optimal;

    /// <summary>加密算法标识（注册表中的 AlgorithmId）；null 表示不加密。</summary>
    public string? EncryptionAlgorithm { get; set; }

    /// <summary>加密口令。<see cref="EncryptionAlgorithm"/> 非空时必填。</summary>
    public string? Password { get; set; }

    /// <summary>KDF 迭代次数（国密 SM4-GM 等支持自定义 KDF 的算法）。默认 10000。</summary>
    public int KdfIterations { get; set; } = 10_000;

    /// <summary>
    /// 直接注入加密提供者（优先于 <see cref="EncryptionAlgorithm"/> 查找注册表）。
    /// 用于第三方自定义算法。
    /// </summary>
    public IEncryptionProvider? EncryptionProvider { get; set; }

    /// <summary>条目名编码。默认 UTF-8（并设置 ZIP UTF-8 标志）。</summary>
    public Encoding EntryNameEncoding { get; set; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    /// <summary>写入注释放置处（部分格式支持归档级注释）。</summary>
    public string? ArchiveComment { get; set; }

    /// <summary>时间戳策略：条目未提供 LastWriteTime 时使用当前时间。</summary>
    public DateTimeOffset? DefaultLastWriteTime { get; set; }

    /// <summary>进度接收器（可选）。与门面层事件并行可用。</summary>
    public IProgress<ArchiveProgress>? Progress { get; set; }

    /// <summary>
    /// 是否允许写入弱加密 ZipCrypto（默认 false，需显式启用；仅限遗留兼容场景）。
    /// </summary>
    public bool AllowWeakZipCrypto { get; set; }

    internal ArchiveWriteOptions CloneForFormat() => new()
    {
        Level = Level,
        EncryptionAlgorithm = EncryptionAlgorithm,
        Password = Password,
        KdfIterations = KdfIterations,
        EntryNameEncoding = EntryNameEncoding,
        ArchiveComment = ArchiveComment,
        DefaultLastWriteTime = DefaultLastWriteTime,
        Progress = Progress,
        AllowWeakZipCrypto = AllowWeakZipCrypto,
    };

    internal IEncryptionProvider? ResolveProvider(GeneralZipEncryptionRegistry registry)
    {
        if (EncryptionProvider != null)
        {
            return EncryptionProvider;
        }

        if (EncryptionAlgorithm == null)
        {
            return null;
        }

        var provider = registry.Find(EncryptionAlgorithm);
        if (provider == null)
        {
            throw new UnsupportedFormatException($"Unregistered encryption algorithm: {EncryptionAlgorithm}");
        }

        if (!provider.SupportsWrite)
        {
            throw new NotSupportedException($"Encryption algorithm {provider.AlgorithmId} does not support writing");
        }

        if (Password == null)
        {
            throw new ArgumentException($"Algorithm {provider.AlgorithmId} requires a password (options.Password)", nameof(Password));
        }

        return provider;
    }
}
