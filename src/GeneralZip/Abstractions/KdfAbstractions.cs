using System;

namespace GeneralZip.Abstractions;

/// <summary>
/// 密钥派生函数（KDF）提供者。口令 → 密钥材料。
/// 实现要求：无状态、线程安全；可经 <c>GeneralZipEncryptionRegistry.Kdfs.Register</c> 注册。
/// <para>SM4-GM 容器规范（CRYPTO-SPEC.md）在 extra field 中以 1 字节 <see cref="SpecId"/>
/// 标识 KDF：1 = SM3-PBKDF2（内置），2 = PBKDF2-HMAC-SHA256（内置），自定义算法请避开已占用值。</para>
/// </summary>
public interface IKdfProvider
{
    /// <summary>容器规范中的 1 字节 KDF 标识（SM4-GM extra field 使用）。</summary>
    byte SpecId { get; }

    /// <summary>注册表内的唯一标识名（如 "SM3-PBKDF2"、"PBKDF2-SHA256"）。</summary>
    string KdfId { get; }

    /// <summary>从口令派生 outputLength 字节的密钥材料。</summary>
    /// <param name="password">UTF-8 口令。</param>
    /// <param name="salt">盐。</param>
    /// <param name="iterations">迭代/工作量参数（实现自行解释语义，0 = 实现默认值）。</param>
    /// <param name="outputLength">输出字节数。</param>
    byte[] Derive(string password, byte[] salt, int iterations, int outputLength);
}

/// <summary>
/// 标记接口：写路径不需要口令的加密提供者（如 SM2-GM 信封：写侧只需接收方公钥）。
/// 未实现本接口的提供者在 <see cref="ArchiveWriteOptions.Password"/> 缺失时于解析期报错。
/// </summary>
public interface IPasswordlessWriteProvider
{
}
