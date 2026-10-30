<div align="center">

# GeneralZip

**跨格式、可加密（含国密）、事件驱动的 .NET 压缩组件**

[![CI](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/ci.yml/badge.svg)](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/ci.yml)
[![Release](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/release.yml/badge.svg)](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-netstandard2.0%20%7C%20net8.0-blueviolet)](https://learn.microsoft.com/dotnet/standard/net-standard)

[English](README.en.md) | [**中文**](README.md)

</div>

---

## 为什么选择 GeneralZip？

- **一套 API 覆盖多种格式** —— ZIP、7z、RAR、TAR、GZ、BZ2、XZ、Zstd、LZ4，魔数自动探测。再也不用为某个文件找专门的库。
- **正确的加密** —— WinZip AES 通用互通；**SM4-GM 国密**以文档化的自定义 ZIP 扩展实现；所有算法通过一个 `EncryptionAlgorithm` 开关切换。
- **为应用而生** —— 完整事件系统（进度、交互取密、覆盖决策、错误策略）、全 API `CancellationToken`、`IProgress<T>` 支持。
- **核心包零第三方 NuGet 依赖** —— 密码学原语（SM3/SM4）与 TAR 容器为纯 C# 实现，经 GB/T 标准向量锁定；原生编解码（7z/bzip2/xz/zstd/lz4）位于可选的 Rust 原生核心，全部纯 Rust。

## 安装

```
dotnet add package GeneralZip
```

目标框架 `netstandard2.0` 与 `net8.0`。

> 一个包，能力齐全。包内已捆绑 win-x64、linux-x64、linux-musl-x64、osx-x64、osx-arm64
> 五个平台的预编译 Rust 原生核心，`GeneralZip.Initialize()` 会自动加载；
> 若平台无对应核心，7z/RAR 与原生编解码优雅降级，其余能力不受影响。

## 快速开始

### 一行式压缩 / 解压

```csharp
using GeneralZip;

GeneralZip.Initialize();  // 幂等引导

// 目录 → 归档（格式由扩展名决定）
await GeneralZip.CompressAsync(@"C:\data", @"D:\backup.zip");

// 归档 → 目录
var result = await GeneralZip.ExtractAsync(@"D:\backup.zip", @"D:\restore");
Console.WriteLine($"解压 {result.ProcessedCount} 个条目，失败 {result.FailedCount}");
```

### 加密归档

```csharp
using GeneralZip;
using GeneralZip.Abstractions;

// 写入：SM4-GM 国密 —— 规范见 docs/CRYPTO-SPEC.md
await GeneralZip.CompressAsync(@"C:\data", @"D:\backup.zip", o =>
{
    o.Level = CompressionLevelChoice.Optimal;
    o.EncryptionAlgorithm = "SM4-GM";          // 通用互通场景用 "WinZipAES256"
    o.Password = password;                     // 从密钥管理服务获取，切勿硬编码
    o.KdfIterations = 10_000;                  // SM3-PBKDF2 迭代次数
});

// 读取：错误口令快速失败（条目级校验值），不会静默产生坏数据
using var reader = GeneralZipReader.Open(@"D:\backup.zip", o => o.Password = password);
var entry = reader.Entries[0];
using var stream = reader.OpenEntryStream(entry);   // 惰性解密 + 解压流
```

### 流式 API 与事件

```csharp
using GeneralZip;
using GeneralZip.Abstractions;

// 带进度创建归档
using var writer = GeneralZipWriter.CreateNew(@"D:\photos.zip", o =>
{
    o.Level = CompressionLevelChoice.SmallestSize;
    o.Progress = new Progress<ArchiveProgress>(p =>
        Console.Write($"\r{p.Percent:F0}% {p.CurrentEntry}"));
});
writer.AddFile(@"C:\a.pdf", "docs/a.pdf");
await writer.AddDirectoryAsync(@"C:\photos", "photos");
await writer.FinishAsync();     // Dispose 未 Finish 时也会自动收尾
```

```csharp
// 交互取密、覆盖与错误处理
using var reader = GeneralZipReader.Open(archivePath, configure: null, r =>
{
    // 整包加密格式（如 7z 头部加密）请在此订阅 —— Open 期间就可能需要口令。
    r.PasswordRequired += (_, e) =>
    {
        e.Password = PromptPassword(e.EntryName, e.Attempt);   // 你的 UI 逻辑
        if (e.Attempt >= 3) e.Cancel = true;                   // 3 次后放弃
    };
    r.OverallProgress += (_, p) => UpdateProgressBar(p.Percent, p.Eta);
});

var result = reader.ExtractToDirectory(@"D:\out", new ExtractionOptions
{
    OverwritePolicy = OverwritePolicy.Ask,      // 触发 reader.OverwriteQuery
    ErrorPolicy = ErrorPolicy.RaiseEvent,       // 触发 reader.ErrorReport（重试/跳过/中止）
    Filter = e => e.FullName.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase),
});
```

### 完整性测试

```csharp
// 明文归档无需口令；加密归档需提供口令
using var testReader = GeneralZipReader.Open(path, o => o.Password = password);
var test = testReader.TestAll();
Console.WriteLine(test.Success ? "OK" : $"{test.FailedCount} 个条目失败");
```

### 格式探测与扩展

```csharp
var info = GeneralZip.DetectFormat(mysteryFile);    // 魔数优先，扩展名兜底
Console.WriteLine(info?.Name);                      // "ZIP"、"7Z"、"TAR.GZ" ...

// 注册自定义格式或加密算法
GeneralZip.Registry.Register(new MyArchiveFormat());
GeneralZip.Encryption.Register(new MyEncryptionProvider());
```

> 引导类与组件同名（`namespace GeneralZip` 中的 `class GeneralZip`）。
> 若需要与其它类型限定写法混用，可用 `using static GeneralZip.GeneralZip;` 裸调用 `Initialize()` / `CompressAsync()` 等。

## 格式与加密矩阵

| 格式 | 读 | 写 | 加密读 | 加密写 |
|---|:---:|:---:|:---:|:---:|
| ZIP（Store/Deflate/Zip64） | ✓ | ✓ | ZipCrypto / WinZip AES / **SM4-GM** | ✓ |
| 7z（LZMA2） | ✓ | ✓ | AES-256 | AES-256 |
| RAR4/RAR5 | ✓ | —（专有） | ✓ 密码 | — |
| TAR / TAR.GZ | ✓ | ✓ | — | — |
| GZ | ✓（.NET 内置） | ✓（.NET 内置） | — | — |
| BZ2 / XZ / ZSTD / LZ4 | ✓（原生核心） | ✓（原生核心） | — | — |

> 7z/RAR 与 BZ2/XZ/ZSTD/LZ4 由 **Rust 原生核心**提供（全部纯 Rust crate）。
> 核心缺失时优雅降级：ZIP/TAR/TAR.GZ/GZ（纯托管）与全部 ZIP 系加密不受影响。

**部分 "—" 的原因：**

- **RAR 不可写** —— RAR 压缩算法为 RARLAB 专有，公开的 unrar 许可证明确禁止将其用于实现
  压缩器，全球只有 WinRAR 能生成 RAR 文件（7-Zip、libarchive 等同样只读不写）。
  读取（含密码解密）由原生核心完整支持。
- **TAR / GZ / BZ2 / XZ / ZSTD / LZ4 的加密列** —— 这些格式的规范中根本不存在加密机制：
  TAR 是纯"头 + 数据"容器，单文件编解码器也没有存放 KDF 参数、IV 或认证标签的位置。
  需要加密时可在应用层"先加密后压缩"，或改用 ZIP + WinZip AES / SM4-GM。
- **SM4-GM 仅落地于 ZIP 是刻意设计** —— ZIP 的 extra field 机制天生支持第三方扩展，
  SM4-GM 容器的二进制规范已在 [docs/CRYPTO-SPEC.md](docs/CRYPTO-SPEC.md) 完整文档化，
  供第三方实现互通；向 7z 这类标准化容器注入自定义加密会产出其他工具无法打开的归档。
- **ZipCrypto 写入默认关闭**（遗留 56 位弱加密），需显式启用；
  正式场景请选择 WinZip AES（通用互通）或 SM4-GM（国密合规）。

## 从源码构建

```powershell
.\build\build.ps1              # Rust 原生核心 + 托管构建 + 全部测试
.\build\build.ps1 -SkipNative  # 仅托管部分（7z/RAR 与原生编解码不可用）
```

前置要求：
- .NET SDK 8.0+
- Rust（仅原生核心需要）—— Windows 建议 GNU 工具链：
  ```powershell
  rustup-init.exe -y --default-toolchain stable-x86_64-pc-windows-gnu --profile minimal
  ```
- RAR 支持（`rar` cargo feature）：额外需要 MSVC，默认关闭

### 手动部署原生核心

将 `generalzip_native.dll/.so/.dylib` 放到以下任一位置：
1. 应用程序目录；
2. 应用目录下的 `runtimes/<RID>/native/`；
3. `GENERALZIP_NATIVE` 环境变量指向的路径，

然后启动时调用一次 `GeneralZip.Initialize()`（一行式 API 内部已自动调用）。

## 示例文件

[samples/fixtures/](samples/fixtures/README.md) 内置**全部支持格式**的样例归档
（10 种明文 + 4 种加密变体），含公开演示口令与明文 SHA-256 校验值，
同时作为跨版本兼容性锚点由测试套件自动验证。

## 性能基准

全部格式的吞吐数据（含各加密算法的开销对比），由
[samples/GeneralZip.Bench](samples/GeneralZip.Bench/Program.cs) 测量：[docs/BENCHMARKS.md](docs/BENCHMARKS.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 分层架构、接口契约、事件协议、Rust FFI 设计 |
| [docs/CRYPTO-SPEC.md](docs/CRYPTO-SPEC.md) | SM4-GM 加密 ZIP 容器二进制规范（第三方互通依据） |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | 全格式性能数据 |
| [samples/](samples/) | 可运行示例：基础用法、事件、基准、fixture 生成器 |

## 项目结构

```
src/GeneralZip/           组件库（托管核心 + 内置 Rust 原生核心绑定）
native/generalzip-native/ Rust cdylib：7z/bzip2/xz/zstd/lz4 编解码（C ABI）
native/dlltool-shim-rs/   windows-gnu raw-dylib 构建辅助
tests/                    73 个测试：标准向量、互操作 oracle、事件、fixtures
samples/                  示例 + 示例归档（fixtures）
build/                    一键构建脚本
```

## 已知限制

- RAR **仅读取** —— 压缩算法专有，任何合规实现均无法创建 RAR。
- 7z 归档不支持追加（每次写入生成完整新包）。
- SM4-GM 为自定义规范（ZIP 无官方 SM4 标准）；互通限于本组件与实现同一规范的第三方。
- BZ2/XZ/ZSTD/LZ4 依赖原生核心；GZip 始终可用（纯托管）。
- 原生 zstd 压缩为一次性内存 API；xz/lz4/bzip2 为流式。

## 依赖与许可

**核心包零第三方 NuGet 依赖**——除微软官方维护的包外，不引用任何第三方 NuGet：

| 组件 | 用途 | 维护方 |
|---|---|---|
| System.IO.Compression / System.Security.Cryptography | Deflate、GZip 容器、AES、SHA1、PBKDF2-SHA1 | 微软官方 |
| SM3 / SM4 / HMAC-SM3 / PBKDF2-SM3 / TAR(ustar) / CRC32 | 本组件纯 C# 自研实现（GB/T 标准向量锁定） | GeneralZip |
| Microsoft.Bcl.AsyncInterfaces | netstandard2.0 异步 API 填充 | 微软官方 |
| Rust 原生核心：sevenz-rust2 / lzma-rs / lzma_rust2 / bzip2(libbz2-rs) / lz4_flex / rust-zstd | 7z、xz、bzip2、lz4、zstd 编解码 | Rust 社区（各依上游） |

欢迎 Issue 与 PR。提交前请运行 `build\build.ps1` 并确保全部测试通过。
基于 [MIT License](LICENSE) 发布。
