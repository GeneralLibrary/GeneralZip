# GeneralZip

<div align="right">

[**中文**](README.zh-CN.md) | [English](README.en.md)

</div>

跨格式、可加密（含国密）、事件驱动的 .NET 压缩组件。

```csharp
// 启动引导（幂等）+ 一行式：压缩 / 解压 / 测试
GeneralZip.Initialize();
await GeneralZip.CompressAsync(@"C:\data", @"D:\backup.zip",
    o => { o.Level = CompressionLevelChoice.Optimal;
           o.EncryptionAlgorithm = "SM4-GM";       // 国密加密
           o.Password = "强口令-从密钥管理获取"; });

await GeneralZip.ExtractAsync(@"D:\backup.zip", @"D:\restore");

// 事件驱动 + 流式
using var reader = ArchiveReader.Open(@"D:\arch.7z", o => o.Password = "...", r =>
{
    r.PasswordRequired += (_, e) => e.Password = AskUser();   // 交互取密
    r.OverallProgress  += (_, p) => ShowProgress(p);          // 进度/速度/ETA
});
await reader.ExtractToDirectoryAsync(@"D:\out");
```

> 引导类与组件同名（`namespace GeneralZip` 中的 `class GeneralZip`）。
> 推荐写法 `using GeneralZip;` + `using static GeneralZip.GeneralZip;`，即可裸调用 `Initialize()` / `CompressAsync()` 等。

## 特性

| 能力 | 说明 |
|---|---|
| 广格式 | ZIP / 7z / RAR / TAR / TAR.GZ / TAR.BZ2 / GZ / BZ2 / XZ / Zstd / LZ4 |
| 加密矩阵 | ZipCrypto、**WinZip AES-128/256**（通用互通）、**SM4-GM 国密**（自研规范）、7z AES-256、RAR（读） |
| 国密方案 | SM3-PBKDF2 派生 + SM4-CTR + SM3-HMAC（Encrypt-then-MAC），二进制规范见 [docs/CRYPTO-SPEC.md](docs/CRYPTO-SPEC.md) |
| 事件系统 | 条目级进度、总进度（速度/ETA）、`PasswordRequired` 协商（重试计数/缓存）、`OverwriteQuery`、`ErrorReport`（重试/跳过/中止） |
| 编码友好 | 一行式门面 + 流式 API、全 `CancellationToken`、`IProgress<T>`、`netstandard2.0` + `net8.0` 双目标 |
| 可插拔 | `IArchiveFormat` / `IEncryptionProvider` 均可第三方注册扩展 |
| 安全默认 | zip-slip 防护、ZipCrypto 写入默认禁用（显式开启）、HMAC 篡改必拒、错误口令快速失败、常数时间比较 |

## 格式与加密矩阵

| 格式 | 读 | 写 | 加密读 | 加密写 |
|---|---|---|---|---|
| ZIP（Store/Deflate/Zip64） | ✓ | ✓ | ZipCrypto / WinZip AES / **SM4-GM** | 同左 |
| 7z（LZMA2） | ✓ | ✓ | AES-256 | AES-256 |
| RAR4/RAR5 | ✓ | —（专有） | ✓ 密码 | — |
| TAR / TAR.GZ | ✓ | ✓ | — | — |
| GZ | ✓（.NET 内置） | ✓（.NET 内置） | — | — |
| BZ2 / XZ / ZSTD / LZ4 | ✓（原生核心） | ✓（原生核心） | — | — |

> 7z/RAR 与 BZ2/XZ/ZSTD/LZ4 由 **Rust 原生核心**提供（全部纯 Rust 实现）。核心缺失时优雅降级：ZIP/TAR/TAR.GZ/GZ（纯托管）与全部 ZIP 系加密不受影响。

## 构建与测试

```powershell
.\build\build.ps1              # Rust 原生核心 + 托管 + 全部测试
.\build\build.ps1 -SkipNative  # 仅托管部分（7z/RAR/xz写 将不可用）
```

前置要求：
- .NET SDK 8.0+（多目标 netstandard2.0 + net8.0）
- Rust（仅原生核心需要）：建议 GNU 工具链 + 国内镜像
  ```powershell
  $env:RUSTUP_DIST_SERVER="https://rsproxy.cn"; $env:RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"
  rustup-init.exe -y --default-toolchain stable-x86_64-pc-windows-gnu --profile minimal
  ```
- RAR 支持（`rar` cargo feature）：额外需要 C++ 工具链（MSVC），默认关闭

原生核心部署（应用侧）：将 `generalzip_native.dll/.so/.dylib` 放到应用目录、
`runtimes/<RID>/native/`，或设置 `GENERALZIP_NATIVE` 环境变量；启动时调用
`GeneralZipNative.Initialize()` 一次即可。

## 使用示例

完整可运行示例见 [samples/GeneralZip.Samples](samples/GeneralZip.Samples/Program.cs)，覆盖：
一行式压缩、国密加密往返、事件驱动（进度/密码/错误策略）、7z 加密读写、xz 编解码、完整性测试。

### API 速览

```csharp
// 打开 + 格式自动探测（魔数优先）
using var reader = ArchiveReader.Open(path);
foreach (var entry in reader.Entries) { /* FullName/Size/IsEncrypted/... */ }
using Stream s = reader.OpenEntryStream(entry);        // 惰性解压流

// 解压策略
var result = reader.ExtractToDirectory(dest, new ExtractionOptions {
    OverwritePolicy = OverwritePolicy.Ask,             // 触发 OverwriteQuery
    ErrorPolicy     = ErrorPolicy.RaiseEvent,          // 触发 ErrorReport
    Filter          = e => e.FullName.EndsWith(".pdf"),
});

// 写入（顺序 API，支持不可寻址流）
using var writer = ArchiveWriter.CreateNew(outPath, o =>
{
    o.Level = CompressionLevelChoice.SmallestSize;
    o.EncryptionAlgorithm = "WinZipAES256";
    o.Password = password;
});
writer.AddFile(@"C:\a.pdf", "docs/a.pdf");
writer.AddDirectory(@"C:\photos", "photos");
await writer.FinishAsync();                            // Dispose 未 Finish 时自动收尾

// 扩展点：注册自定义格式 / 加密算法
GeneralZip.Registry.Register(new MyArchiveFormat());
GeneralZip.Encryption.Register(new MyEncryptionProvider());
```

## 架构文档与基准

> 🌐 文档语言（i18n）：详细设计文档目前仅提供中文；英文 README 为功能与使用概览。

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) —— 分层架构、接口契约、事件协议、Rust FFI 设计、扩展指南
- [docs/CRYPTO-SPEC.md](docs/CRYPTO-SPEC.md) —— 国密 SM4-GM 加密 ZIP 容器二进制规范（第三方互通实现依据）
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) —— 全格式压缩/解压吞吐基准（含加密开销对比），由 `samples/GeneralZip.Bench` 生成
- [samples/fixtures/](samples/fixtures/README.md) —— 加密示例文件（SM4-GM / WinZip AES / ZipCrypto / 7z AES，含口令与 SHA-256 校验值），并作为跨版本兼容性回归锚点

## 依赖与许可

**核心包零第三方 NuGet 依赖**——除微软官方维护的包外，不引用任何第三方 NuGet：

| 组件 | 用途 | 维护方 |
|---|---|---|
| System.IO.Compression / System.Security.Cryptography | Deflate、GZip 容器、AES、SHA1、PBKDF2-SHA1 | 微软官方 |
| SM3 / SM4 / HMAC-SM3 / PBKDF2-SM3 / TAR(ustar) / CRC32 | 本组件纯 C# 自研实现（GB/T 标准向量锁定） | GeneralZip |
| Microsoft.Bcl.AsyncInterfaces | netstandard2.0 异步 API 填充 | 微软官方 |
| Rust 原生核心：sevenz-rust2 / lzma-rs / lzma_rust2 / bzip2(libbz2-rs) / lz4_flex / rust-zstd | 7z、xz、bzip2、lz4、zstd 编解码 | Rust 社区（各依上游） |

非压缩类密码学原语（SM3/SM4/国密 HMAC）为纯 C# 自研并经 GB/T 标准向量锁定；
压缩 codecs（bzip2/xz/zstd/lz4/7z）集中于 Rust 原生核心，全部为纯 Rust 实现（无 C 工具链依赖）。

本项目代码 MIT。

## 已知限制（v1.1）

- RAR 仅读取（WinRAR 压缩算法专有，任何合规实现均无法创建）
- 7z 归档不支持向既有包追加（每次创建为整包写入）
- SM4-GM 为自定义规范（ZIP 无官方 SM4 标准），互通限于本组件与按规范实现的第三方
- **BZ2 / XZ / ZSTD / LZ4 编解码依赖原生核心**：核心缺失时这些格式不可用（ZIP/TAR/GZ/7z/RAR 不受影响）；GZip 为 .NET 内置实现，始终可用
- 原生 zstd 压缩为一次性内存 API（大文件压缩占用与源文件等量内存）；xz/lz4/bzip2 为流式
- 读取加密 7z/大文件时逐条目解压到临时文件（支持随机访问语义；顺序大批量解压后续版本提供批处理路径）
