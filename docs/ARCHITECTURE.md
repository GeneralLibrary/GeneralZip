# GeneralZip 架构设计文档

> 跨格式、可加密（含国密）、事件驱动、编码友好的 .NET 压缩组件

## 1. 设计目标

| 目标 | 说明 |
|---|---|
| 广格式覆盖 | ZIP / 7z / RAR / TAR / GZ / BZ2 / XZ / Zstd / LZ4 的读写（RAR 仅读） |
| 完整加密能力 | ZipCrypto、WinZip AES-128/256、7z AES-256、RAR AES（读）、**SM4-GM 国密** |
| 事件驱动 | 进度、密码协商、覆盖冲突、错误策略全链路事件化 |
| 编码友好 | 一行式门面 API + 流式 API 双形态；全异步 + `CancellationToken`；`IProgress<T>` 原生支持 |
| 可插拔 | 格式提供者、加密提供者均为可注册扩展点 |
| 优雅降级 | Rust 原生核心缺失时，托管功能不受影响，7z/RAR 提供者自动停用 |

## 2. 总体分层

```
┌────────────────────────────────────────────────────────────┐
│ 门面层   GeneralZip (静态引导/门面) /                        │ 一行式与流式 API
│          GeneralZipReader / GeneralZipWriter                 │
├────────────────────────────────────────────────────────────┤
│ 事件层   EntryStarted / EntryProgress / EntryCompleted /    │ 进度
│          EntryFailed / OverallProgress /                    │ 交互
│          PasswordRequired / OverwriteQuery / ErrorReport    │ 错误策略
├────────────────────────────────────────────────────────────┤
│ 抽象层   IArchiveFormat · IArchiveReader · IArchiveWriter   │ 可插拔扩展点
│          IArchiveEntry · IEncryptionProvider ·              │
│          ArchiveFormatRegistry · ArchiveSignatureProbe      │
│          （魔数探测内置于 ArchiveFormatRegistry.Detect）      │
├──────────────┬───────────────────────┬─────────────────────┤
│ 格式提供者    │ 加密提供者             │ 原生核心 (Rust, 纯Rust)│
│  ZipFormat   │  ZipCryptoProvider    │  generalzip-native   │
│  Tar/TarGz   │  WinZipAesProvider    │  · 7z: sevenz-rust2  │
│  GZip(.NET)  │  Sm4GmProvider(国密)   │  · RAR: unrar (可选)  │
│  Bz2/Xz/     │  (SM2 信封扩展点预留)   │  · xz: lzma-rs+      │
│  Zstd/Lz4    │                       │    lzma_rust2        │
└──────────────┴───────────────────────┴─────────────────────┤
│  Bz2/Xz/Zstd/Lz4 编解码经 NativeBridge 路由到原生核心          │
│  GZip = .NET GZipStream；TAR/SM3/SM4 = 组件纯 C# 自研          │
└─────────────────────────────────────────────────────────────┘
         GeneralZip (零第三方 NuGet)   GeneralZip.Native (P/Invoke 包装)
```

- **门面层**不包含任何格式逻辑，只做编排：格式探测 → 提供者选择 → 事件桥接。
- **抽象层**是唯一稳定契约，格式/加密实现均可第三方扩展。
- **GeneralZip 核心包零 P/Invoke**；原生交互完全隔离在 `GeneralZip.Native` 包内。

## 3. 项目结构

```
GeneralZip.sln
├─ docs/
│  ├─ ARCHITECTURE.md            本文档
│  └─ CRYPTO-SPEC.md             SM4-GM 容器二进制规范（国密互通依据）
├─ native/generalzip-native/     Rust crate (cdylib, C ABI)
├─ src/
│  ├─ GeneralZip/                核心包（netstandard2.0 + net8.0）
│  │  ├─ Abstractions/           接口、选项、枚举、ArchiveEntry 基础类型
│  │  ├─ Events/                 事件参数与进度快照
│  │  ├─ Crypto/                 KDF、加密提供者、ArchiveCryptoStream
│  │  ├─ Formats/
│  │  │  ├─ Zip/                 自研 ZIP 读写（含 Zip64、加密挂接）
│  │  │  ├─ Tar/                 TAR / TAR.GZ / TAR.BZ2
│  │  │  └─ Codecs/              GZ/BZ2/XZ/Zstd/LZ4 单文件编解码格式
│  │  ├─ GeneralZip.cs           启动引导 + 静态门面（一行式 API）
│  │  ├─ ArchiveReader.cs        读取封装（事件源）
│  │  ├─ ArchiveWriter.cs        写入封装（事件源）
│  │  ├─ ArchiveFormatRegistry.cs 格式注册表 + 魔数探测
│  └─ GeneralZip.Native/         Rust 核心 P/Invoke 包装（能力协商 + 降级）
├─ tests/
│  ├─ GeneralZip.Tests/          核心测试（含互操作 oracle）
│  └─ GeneralZip.Native.Tests/   Rust 核心集成测试
├─ samples/                      控制台示例
└─ build/build.ps1               一键构建（cargo → 拷贝 → dotnet test）
```

## 4. 核心抽象

### 4.1 格式提供者 IArchiveFormat

```csharp
public interface IArchiveFormat
{
    string Name { get; }                        // "ZIP" / "7Z" / "RAR" ...
    IReadOnlyList<string> Extensions { get; }   // [".zip"]
    FormatCapabilities Capabilities { get; }    // Read/Write/EncryptedRead/EncryptedWrite/SeekableRead
    bool MatchesSignature(Stream stream);       // 魔数探测（优先于扩展名）
    bool MatchesExtension(string extension);
    IArchiveReader OpenRead(Stream stream, ArchiveOpenOptions options);
    IArchiveWriter OpenWrite(Stream stream, ArchiveWriteOptions options);
}
```

约定：
- 提供者**无状态**（每次 Open 返回独立实例），可安全注册为单例。
- `OpenRead` 读取头部后立即返回；条目数据**惰性解压**（流式，不一次性载入内存）。
- 不支持的组合（如向 RAR 写入）抛 ` NotSupportedException` 而非静默失败。

### 4.2 读取 IArchiveReader

```csharp
public interface IArchiveReader : IDisposable
{
    ArchiveFormatInfo Format { get; }
    IReadOnlyList<IArchiveEntry> Entries { get; }
    bool IsEncrypted { get; }
    Stream OpenEntryStream(IArchiveEntry entry);
    void ExtractToDirectory(string destinationDirectory, ExtractionOptions? options = null, CancellationToken ct = default);
    void ExtractEntry(IArchiveEntry entry, string destinationPath, ExtractionOptions? options = null, CancellationToken ct = default);
    void TestAll(ExtractionOptions? options = null, CancellationToken ct = default);
}
```

### 4.3 写入 IArchiveWriter

```csharp
public interface IArchiveWriter : IDisposable, IAsyncDisposable
{
    void AddFile(string filePath, string? entryName = null);
    Task AddFileAsync(string filePath, string? entryName = null, CancellationToken ct = default);
    void AddDirectory(string directoryPath, string? entryPrefix = null, Predicate<string>? filter = null);
    Task AddDirectoryAsync(string directoryPath, string? entryPrefix = null, Predicate<string>? filter = null, CancellationToken ct = default);
    void AddStream(string entryName, Stream content, long? size = null, DateTimeOffset? lastWriteTime = null);
    Task FinishAsync(CancellationToken ct = default);   // 写入中央目录并收尾
}
```

写入器为**顺序写入**模型：条目逐个落盘（配合数据描述符），`FinishAsync` 补写中央目录。
ZIP 的"追加/删除条目"操作 v1 以"读出→重写"语义在门面层提供，不在写入器内维护随机访问。

### 4.4 条目 IArchiveEntry

```csharp
public interface IArchiveEntry
{
    string FullName { get; }          // 统一 '/' 分隔
    string Name { get; }              // 文件名部分
    long Size { get; }
    long CompressedSize { get; }
    DateTimeOffset? LastWriteTime { get; }
    bool IsDirectory { get; }
    bool IsEncrypted { get; }
    string? EncryptionAlgorithm { get; }  // "WinZipAES256" / "SM4-GM" / ...
    uint? Crc32 { get; }
    string? Comment { get; }
}
```

### 4.5 加密提供者 IEncryptionProvider

```csharp
public interface IEncryptionProvider
{
    string AlgorithmId { get; }                    // "ZipCrypto" / "WinZipAES256" / "SM4-GM"
    bool SupportsWrite { get; }
    bool SupportsRead { get; }

    // 写路径：对"已压缩数据"加密（Encrypt-then-MAC 语义由实现保证）
    Stream CreateEncryptionStream(Stream destination, EncryptionContext context);
    // 读路径：对"密文流"解密；口令错误抛 InvalidPasswordException
    Stream CreateDecryptionStream(Stream source, EncryptionReadContext context);
}

public sealed class EncryptionContext
{
    public string Password { get; }
    public long PlainSize { get; }        // -1 = 未知（流式）
    public uint Crc32 { get; }            // 已知时用于校验/口令校验值
    public IDictionary<string, object?> Properties { get; }  // 算法参数（盐/IV/迭代数）读写通道
}
```

关键设计：**ZIP 格式引擎不认识任何具体算法**。它只负责：
1. 写：压缩流 → `IEncryptionProvider.CreateEncryptionStream` → 落盘；把 `Properties` 中算法回填的参数（盐/IV/校验值）序列化进 extra field。
2. 读：识别 extra field → 选出 `AlgorithmId` 匹配的提供者 → 包一层解密流。

因此新增国密/自定义算法**零侵入**格式层——这正是 `IEncryptionProvider` 独立于 `IArchiveFormat` 存在的意义。

## 5. 事件通知机制

### 5.1 事件清单

| 事件 | 触发时机 | 典型用途 |
|---|---|---|
| `EntryStarted` | 某条目开始压缩/解压 | UI 显示当前文件 |
| `EntryProgress` | 条目内字节级推进（约每 64KB 聚合一次） | 单文件进度条 |
| `EntryCompleted` / `EntryFailed` | 条目成功/失败 | 统计、日志 |
| `OverallProgress` | 全局进度推进 | 总进度条 |
| `PasswordRequired` | 遇到加密条目且缓存中无口令 | 弹窗取密、重试计数 |
| `OverwriteQuery` | 解压目标文件已存在且策略为 Ask | 覆盖/跳过/重命名 |
| `ErrorReport` | 条目级错误且策略为 RaiseEvent | 跳过/重试/中止决策 |

### 5.2 进度快照（不可变记录）

```csharp
public sealed record ArchiveProgress(
    ArchivePhase Phase,           // Analyzing/Compressing/Decompressing/Testing/Finalizing
    string? CurrentEntry,
    long EntriesCompleted, long? EntriesTotal,
    long BytesProcessed,  long? BytesTotal,
    double? Percent,              // 0~100，无法计算时为 null
    double? BytesPerSecond,
    TimeSpan? Eta);
```

同时支持两种消费方式：
- **经典事件**：`reader.OverallProgress += ...`（在 `ArchiveReader`/`ArchiveWriter` 上）
- **现代注入**：`options.Progress = new Progress<ArchiveProgress>(...)`（自动线程封送到同步上下文）

两者可并存；进度聚合由内部 `ProgressAggregator` 完成（节流：至少间隔 50ms 或字节增量 >1% 才上报，避免 UI 洪泛）。

### 5.3 密码协商协议

```
遇加密条目 → 查 PasswordCache（会话级，按 Archive+Scope 缓存）
  ├─ 命中 → 直接解密
  └─ 未命中 → 触发 PasswordRequired 事件
        ├─ 处理器设置 e.Password → 存入缓存 → 解密
        ├─ 密码错误 → Attempt+1，重新触发事件（上限 e.MaxAttempts=3，防死循环）
        └─ 无处理器 / e.Cancel=true → 抛 PasswordRequiredException
```

- `PasswordScope`：`SingleEntry`（RAR 分条目加密）| `WholeArchive`（7z 头加密）。
- 编程式用法可跳过事件：`options.Password = "..."` 预置缓存。

### 5.4 错误与覆盖策略

```csharp
public enum ErrorPolicy  { Throw, SkipAll, RaiseEvent }   // 默认 Throw
public enum ErrorAction  { Retry, Skip, Abort }           // 事件内决策
public enum OverwritePolicy { Throw, Overwrite, Skip, Ask, Rename }  // 默认 Throw
```

- 事件处理器内部抛出的异常默认被隔离（`options.PropagateEventExceptions=false`），按 Skip 处理并可配置为透传。
- `Retry` 动作与 `CancellationToken` 正交：取消永远立即生效。

### 5.5 取消语义

所有公开 API 接受 `CancellationToken`；取消后：
- 写路径：删除半成品文件（可配置 `KeepPartialOnCancel`）；
- 读路径：中止当前条目，已解压文件保留；
- 抛 `OperationCanceledException`（不吞不裹）。

## 6. 加密体系

### 6.1 算法矩阵

| AlgorithmId | 格式 | 读 | 写 | 规范 |
|---|---|---|---|---|
| `ZipCrypto` | ZIP | ✓ | ✓(显式启用) | PKWARE 传统加密 |
| `WinZipAES128/256` | ZIP | ✓ | ✓ | AE-2（APPNOTE 0x9901） |
| `SM4-GM` | ZIP | ✓ | ✓ | 自研规范 → `CRYPTO-SPEC.md` |
| `SevenZipAes256` | 7z | ✓ | ✓ | 7z 规范（Rust 核心） |
| `RarAes` | RAR | ✓ | — | 专有（Rust 核心） |

### 6.2 SM4-GM（国密）要点（详见 CRYPTO-SPEC.md）

- 口令派生：**SM3-PBKDF2-HMAC**，域分离双盐 → `K_enc`(16B) + `K_mac`(32B)
- 数据保护：**SM4-CTR**（128 位随机 IV）+ **Encrypt-then-MAC**（SM3-HMAC 全量校验）
- ZIP 载体：自定义 extra field（vendor header `0x6C5A`）携带 版本/KDF 参数/盐/IV/口令校验值（SM3 截断 4B，错误口令快速失败）
- 密码学原语为本组件纯 C# 自研（Sm3Digest/Sm4Engine/HmacSm3 + .NET 内置 AES/SHA1/PBKDF2-SHA1），经 GB/T 标准向量锁定
- 已知答案测试采用 GM/T 0002-2012（SM4）与 GB/T 32907-2016 标准向量

### 6.3 密钥与内存安全

- 派生密钥使用后调用 `CryptographicOperations.ZeroMemory` 清零（netstandard2.0 下 `Array.Clear`）。
- 口令字符串内部即时转 UTF-8 字节参与 KDF，不落地缓存明文口令字节数组（事件传参除外，由调用方掌控）。
- 随机数一律 `RandomNumberGenerator.Fill`。

## 7. Rust 原生核心（generalzip-native）

### 7.1 职责边界

Rust 核心**只做**纯托管生态缺失的能力：7z 读写（含 AES-256 加密）、RAR 解密读取、（附加）xz 编解码。
ZIP/TAR/编解码器等托管可覆盖的能力**不进入** Rust 核心，避免双实现漂移。

### 7.2 FFI 契约（C ABI）

```
gzp_version() -> *const c_char
gzp_capabilities() -> u32                    // bit0: 7z  bit1: rar  bit2: xz
gzp_archive_open(path|stream, password, cbs, user) -> handle
gzp_entry_count(handle) -> i64
gzp_entry_info(handle, index, out_info) -> status
gzp_extract_to(handle, index|all, dest_dir, cb_paths) -> status
gzp_write_begin(path, format, password, opts, cbs, user) -> handle
gzp_write_add(handle, fs_path, entry_name) -> status
gzp_write_finish(handle) -> status
gzp_close(handle) -> status
```

- **回调结构体 `gzp_callbacks`**：`progress_cb(uint64 done, uint64 total, void* user)`、
  `password_cb(uint8* buf, uint32 cap, uint32 attempt, void* user) -> int32`
- `user` 指针由 C# 侧 `GCHandle` 锚定 `CallbackBridge` 对象，委托常驻防回收。
- 边界纪律：**不跨边界抛异常**（Rust 侧 `catch_unwind` 兜底返回 `GZP_ERR_PANIC`）；字符串 UTF-8 显式长度传递；句柄为不透明 `*mut ArchiveHandle`。

### 7.3 能力协商与优雅降级

```
NativeCoreLoader.TryLoad()
  ├─ 按 RID 探测 runtimes/{rid}/native/generalzip_native.{dll|so|dylib}
  │    以及应用目录 / GENERALZIP_NATIVE_PATH 环境变量
  ├─ 载入成功 → gzp_capabilities() → 按 bit 注册 SevenZipFormat / RarFormat
  └─ 载入失败 → 不注册；用户访问 7z/RAR 时抛
       NativeCoreMissingException("...如何安装/部署 native core...")
```

`GeneralZip` 核心包**不引用** `GeneralZip.Native`；宿主应用按需引用后者并调用
`GeneralZipNativeInstaller.Register(registry)`（或在启动时一行 `GeneralZipNative.Initialize();`）。

## 8. 关键流程

### 8.1 创建加密 ZIP

```
GeneralZip.CompressAsync(dir, "out.zip", o => o.EncryptionAlgorithm = "SM4-GM")
→ ZipFormat.OpenWrite
→ for each file:
    File.Open → DeflateStream(压缩)
      → Sm4GmProvider.CreateEncryptionStream (SM4-CTR + SM3-HMAC, EtM)
        → LocalHeader(含 SM4 extra field) + 数据描述符
    每条目: EntryStarted/Progress/Completed
→ FinishAsync: 写 Central Directory + EOCD(Zip64)
→ OverallProgress(100%) → EntryCompleted 汇总
```

### 8.2 解压未知格式加密包

```
ArchiveReader.OpenAsync("mystery.bin")
→ SignatureProbe: 读 16 字节 → 逐提供者 MatchesSignature → 命中 7Z
→ (7Z 为原生提供者) NativeCoreLoader 已注册 → NativeArchiveReader
→ IsEncrypted → PasswordRequired 事件 → 口令 → gzp_archive_open
→ ExtractToDirectoryAsync: 条目循环 + 进度/覆盖/错误事件桥接
```

## 9. 线程模型

- `ArchiveReader`/`ArchiveWriter` 非线程安全（单实例单操作流）；不同实例可并发。
- 事件在**操作线程**触发（async API 下为线程池线程）；`IProgress<T>` 自行封送。
- `PasswordRequired`/`OverwriteQuery` 事件同步阻塞等待应答（UI 线程订阅时经由 `Progress<T>` 模式或 SynchronizationContext 自行调度，文档示例给出 WinForms/WPF 范式）。

## 10. 错误类型体系

```
ArchiveException (基类)
├─ UnsupportedFormatException      格式不支持/无法识别
├─ NativeCoreMissingException      原生核心未部署
├─ PasswordRequiredException       无口令可用（事件未处理且无预置口令）
├─ InvalidPasswordException        口令错误（含 Attempt 次数）
├─ ArchiveCorruptedException       CRC/HMAC 校验失败、结构损坏
└─ ArchiveOperationCanceledException 取消（继承 OperationCanceledException）
```

每个异常携带 `EntryName`（若有），便于日志定位。

## 11. 扩展指南

**新增格式**：实现 `IArchiveFormat` → `ArchiveFormatRegistry.Default.Register(new MyFormat())`。
签名探测自动生效；事件桥接由门面层统一完成，格式实现只需聚焦格式本身。

**新增加密算法**：实现 `IEncryptionProvider` → `registry.Encryption.Register(provider)`。
若为 ZIP 系算法，按 `CRYPTO-SPEC.md` 的 extra field 约定返回参数字典即可。

**替换原生核心**：`NativeCoreLoader.SearchPathProvider` 可注入自定义探测逻辑（如嵌入单文件发布）。

## 12. 版本与兼容

- 组件语义化版本；`ArchiveFormatRegistry.Default` 冻结内置提供者集合，仅追加不破坏。
- SM4-GM 规范版本化（extra field 内 1 字节 version），向后兼容旧包读取。
