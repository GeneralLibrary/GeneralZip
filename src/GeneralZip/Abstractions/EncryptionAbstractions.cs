using System;
using System.Collections.Generic;
using System.IO;

namespace GeneralZip.Abstractions;

/// <summary>写入侧加密上下文：单个条目的口令与元数据。</summary>
public sealed class EncryptionWriteContext
{
    public EncryptionWriteContext(
        string password,
        string entryName,
        uint? crc32,
        long? plainSize,
        ushort realCompressionMethod = 0,
        uint dosTime = 0,
        int kdfIterations = 0)
    {
        Password = password ?? throw new ArgumentNullException(nameof(password));
        EntryName = entryName;
        Crc32 = crc32;
        PlainSize = plainSize;
        RealCompressionMethod = realCompressionMethod;
        DosTime = dosTime;
        KdfIterations = kdfIterations;
    }

    public string Password { get; }

    public string EntryName { get; }

    /// <summary>未压缩数据 CRC-32（已知时）；用于 ZipCrypto 校验字节等。</summary>
    public uint? Crc32 { get; }

    /// <summary>未压缩大小（已知时）；-1 表示流式未知。</summary>
    public long? PlainSize { get; }

    /// <summary>条目真实压缩方法（ZIP extra field 需要，如 8=Deflate）。</summary>
    public ushort RealCompressionMethod { get; }

    /// <summary>条目 DOS 时间戳（ZipCrypto 数据描述符模式的校验字节来源）。</summary>
    public uint DosTime { get; }

    /// <summary>KDF 迭代次数（0 = 算法默认值）。</summary>
    public int KdfIterations { get; }
}

/// <summary>读取侧加密上下文：条目密文与该算法在写入时登记的参数。</summary>
public sealed class EncryptionReadContext
{
    public EncryptionReadContext(
        string password,
        string entryName,
        IReadOnlyDictionary<string, object?> parameters,
        long cipherDataSize)
    {
        Password = password ?? throw new ArgumentNullException(nameof(password));
        EntryName = entryName;
        Parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        CipherDataSize = cipherDataSize;
    }

    public string Password { get; }

    public string EntryName { get; }

    /// <summary>写入时登记的算法参数（如 extra field 原始字节、强度等）。由格式层透传，算法自行解释。</summary>
    public IReadOnlyDictionary<string, object?> Parameters { get; }

    /// <summary>该条目密文数据总长（含算法添加的前缀/尾部）；未知为 -1。</summary>
    public long CipherDataSize { get; }
}

/// <summary>写入计划：算法参数（格式层序列化进归档）与加密流工厂。</summary>
public sealed class EntryEncryptionPlan
{
    public EntryEncryptionPlan(
        ushort? extraFieldId,
        byte[]? extraFieldData,
        long cipherOverhead,
        Func<Stream, Stream> encryptionStreamFactory)
    {
        ExtraFieldId = extraFieldId;
        ExtraFieldData = extraFieldData;
        CipherOverhead = cipherOverhead;
        EncryptionStreamFactory = encryptionStreamFactory ?? throw new ArgumentNullException(nameof(encryptionStreamFactory));
    }

    /// <summary>随条目写入的 ZIP extra field 标识；非 ZIP 算法为 null。</summary>
    public ushort? ExtraFieldId { get; }

    /// <summary>extra field 数据区字节；算法自定义布局（见 CRYPTO-SPEC.md）。</summary>
    public byte[]? ExtraFieldData { get; }

    /// <summary>加密引入的总开销字节数（前缀+尾部），用于预分配/进度；未知为 -1。</summary>
    public long CipherOverhead { get; }

    /// <summary>包装底层目标流为加密流。返回流 Dispose 时刷出 MAC 尾部等收尾数据。</summary>
    public Func<Stream, Stream> EncryptionStreamFactory { get; }
}

/// <summary>
/// 加密算法提供者。格式层（如 ZIP）只依赖本接口完成加密挂接，算法可第三方扩展。
/// 实现要求：无状态、线程安全；每次调用返回独立的流。
/// </summary>
public interface IEncryptionProvider
{
    /// <summary>算法唯一标识，如 "ZipCrypto"、"WinZipAES256"、"SM4-GM"。</summary>
    string AlgorithmId { get; }

    bool SupportsWrite { get; }

    bool SupportsRead { get; }

    /// <summary>本算法在 ZIP 中占用的 extra field 标识集合；非 ZIP 算法返回空集。</summary>
    IReadOnlyCollection<ushort> ZipExtraFieldIds { get; }

    /// <summary>为条目生成加密计划（生成盐/IV/校验值等参数）。</summary>
    EntryEncryptionPlan PrepareWrite(EncryptionWriteContext context);

    /// <summary>依据读取上下文（extra field 参数）创建解密流。</summary>
    /// <exception cref="InvalidPasswordException">口令校验失败。</exception>
    Stream OpenRead(Stream cipherSource, EncryptionReadContext context);
}
