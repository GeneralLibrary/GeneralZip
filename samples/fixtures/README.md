# 示例文件（fixtures）

本目录存放由 GeneralZip 生成的**公开演示用样例归档**，覆盖全部支持的格式：
1. 快速验证本组件的读写能力（无需自行构造）；
2. 作为跨版本兼容性的回归锚点（测试代码逐一校验内容 SHA-256）。

> ⚠️ 加密样例的口令即为本目录公开记录的演示口令，**不承载任何真实数据**；
> 请勿在实际业务中复用。

## 口令（仅加密样例需要）

```
GeneralZip-Demo-2026
```

（源码中由运行时拼接派生，亦可用环境变量 `GENERALZIP_FIXTURE_PASSWORD` 覆盖生成器。）

## 明文样例

| 文件 | 格式 | 条目 | SHA-256 |
|---|---|---|---|
| `sample.zip` | ZIP | `说明.txt` + `data/binary.bin` | 见下方脚本输出 |
| `sample.7z` | 7z（LZMA2） | 同上（含 `data/` 目录条目） | 同上 |
| `sample.tar` | TAR（ustar） | 同上 | 同上 |
| `sample.tar.gz` | TAR.GZ | 同上 | 同上 |
| `sample.tar.bz2` | TAR.BZ2（原生核心） | 同上 | 同上 |
| `sample.gz` | GZIP 单文件 | `sample.gz`（说明文本） | — |
| `sample.bz2` | BZIP2 单文件（原生核心） | `sample.bz2` | — |
| `sample.xz` | XZ 单文件（原生核心） | `sample.xz` | — |
| `sample.zst` | ZSTD 单文件（原生核心） | `sample.zst` | — |
| `sample.lz4` | LZ4 帧单文件（原生核心） | `sample.lz4` | — |

单文件编解码样例的明文即一段说明文本（解压后可直接查看）。
多条目归档的明文 SHA-256（生成器每次运行打印）：

| 条目 | 大小 | SHA-256 |
|---|---|---|
| `说明.txt` | 191 B | `fbe35044f1e479a6f984e72c21df879fde8ca000e5e038d63586822033164752` |
| `data/binary.bin` | 64 KB | `6f171634b41436360023b146b21a4f2c1cb73832546258f3f00e076b70cffb7e` |

## 加密样例

| 文件 | 格式 | 加密算法 | 说明 |
|---|---|---|---|
| `secret-sm4.zip` | ZIP | **SM4-GM**（SM4-CTR + SM3-HMAC，自研国密规范） | 见 [docs/CRYPTO-SPEC.md](../../docs/CRYPTO-SPEC.md) |
| `secret-winzipaes256.zip` | ZIP | WinZip AES-256（AE-2，通用互通） | WinZip/7-Zip/Windows 可解 |
| `secret-zipcrypto.zip` | ZIP | ZipCrypto（PKWARE 传统，弱加密，仅兼容演示） | 勿用于真实数据 |
| `secret-7z-aes256.7z` | 7z | 7z AES-256（LZMA2） | 经 Rust 原生核心 |

加密样例条目同明文多条目归档（SHA-256 同上表）。

## RAR 说明

RAR 为专有压缩格式，组件**仅支持读取**且无法生成样例（无任何合规编码器）。
如需 RAR 样例，请用 WinRAR 自行创建后放入本目录——组件的 RAR 读取能力
（含密码解密）由原生核心提供。

## 验证方法

```csharp
using GeneralZip;

// 多条目归档
using var reader = ArchiveReader.Open("samples/fixtures/sample.tar.gz");
foreach (var entry in reader.Entries)
{
    using var s = reader.OpenEntryStream(entry);
    using var ms = new MemoryStream();
    s.CopyTo(ms);
}

// 加密归档
using var encrypted = ArchiveReader.Open("samples/fixtures/secret-sm4.zip",
    o => o.Password = "GeneralZip-Demo-2026");
```

或运行回归测试（自动逐条目校验内容）：

```powershell
dotnet test tests/GeneralZip.Tests          # ZIP 加密 fixtures + 明文样例
dotnet test tests/GeneralZip.Native.Tests   # 7z fixture + 原生编解码 fixtures
```

## 再生成

```powershell
dotnet run -c Release --project samples/GeneralZip.Fixtures
```

生成器确定性：明文内容固定（文本 + 固定种子 LCG 二进制），
但加密归档本身含随机盐/IV，每次生成的归档字节不同——以明文 SHA-256 为准。
