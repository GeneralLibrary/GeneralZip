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

/// <summary>
/// ZIP 条目压缩方法（仅 ZIP 格式使用；其它格式忽略）。
/// Auto = 空条目/NoCompression 用 Store，其余 Deflate。
/// BZip2/Zstd/Lzma 需要 Rust 原生核心（缺失时抛 NativeCoreMissingException）。
/// </summary>
public enum ZipCompressionMethodChoice
{
    Auto = 0,
    Deflate = 1,
    BZip2 = 2,
    Zstd = 3,
    Lzma = 4,
}

/// <summary>创建归档的选项。</summary>
public sealed class ArchiveWriteOptions
{
    /// <summary>压缩级别。默认 Optimal。</summary>
    public CompressionLevelChoice Level { get; set; } = CompressionLevelChoice.Optimal;

    /// <summary>ZIP 条目压缩方法（其它格式忽略）。默认 Auto（Deflate）。</summary>
    public ZipCompressionMethodChoice ZipCompressionMethod { get; set; } = ZipCompressionMethodChoice.Auto;

    /// <summary>
    /// 并行压缩的最大并发度（当前仅 ZIP 实现条目级分片并行：各条目压缩至独立临时分片，
    /// Finish 时按序装配）。默认 1（顺序压缩）；大于 1 的事件不保证条目顺序。
    /// </summary>
    public int MaxDegreeOfParallelism { get; set; } = 1;

    /// <summary>
    /// 分卷大小（字节）。大于 0 时输出为 x.zip.001/002/... 纯字节分卷（EOCD 落在末卷）；
    /// 读取端打开 x.zip.001 即自动拼接。默认 0 = 单文件。仅 ZIP 等顺序写入格式适用。
    /// </summary>
    public long VolumeSize { get; set; }

    /// <summary>加密算法标识（注册表中的 AlgorithmId）；null 表示不加密。</summary>
    public string? EncryptionAlgorithm { get; set; }

    /// <summary>加密口令。<see cref="EncryptionAlgorithm"/> 非空时必填。</summary>
    public string? Password { get; set; }

    /// <summary>KDF 迭代次数（国密 SM4-GM 等支持自定义 KDF 的算法）。默认 10000。</summary>
    public int KdfIterations { get; set; } = 10_000;

    /// <summary>
    /// KDF 算法标识（注册表 <see cref="GeneralZipEncryptionRegistry.Kdfs"/> 中的 KdfId，
    /// 如 "SM3-PBKDF2"（默认）/ "PBKDF2-SHA256"）；null = 算法默认值。
    /// </summary>
    public string? KdfAlgorithmId { get; set; }

    /// <summary>
    /// 接收方 SM2 公钥（hex；"04||X||Y" 130 字符或 "X||Y" 128 字符）。SM2-GM 信封加密写路径必填。
    /// </summary>
    public string? RecipientPublicKey { get; set; }

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
        ZipCompressionMethod = ZipCompressionMethod,
        MaxDegreeOfParallelism = MaxDegreeOfParallelism,
        VolumeSize = VolumeSize,
        EncryptionAlgorithm = EncryptionAlgorithm,
        Password = Password,
        KdfIterations = KdfIterations,
        KdfAlgorithmId = KdfAlgorithmId,
        RecipientPublicKey = RecipientPublicKey,
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

        // 写路径无需口令的算法（如 SM2-GM 信封，用接收方公钥加密数据密钥）
        if (Password == null && provider is not IPasswordlessWriteProvider)
        {
            throw new ArgumentException($"Algorithm {provider.AlgorithmId} requires a password (options.Password)", nameof(Password));
        }

        return provider;
    }

    /// <summary>解析 KDF 提供者（KdfAlgorithmId → 注册表查找；未设置返回 null = 算法默认）。</summary>
    internal IKdfProvider? ResolveKdf(GeneralZipEncryptionRegistry registry)
    {
        if (KdfAlgorithmId == null)
        {
            return null;
        }

        var kdf = registry.Kdfs.FindByName(KdfAlgorithmId);
        if (kdf == null)
        {
            throw new UnsupportedFormatException($"Unregistered KDF algorithm: {KdfAlgorithmId}");
        }

        return kdf;
    }
}
