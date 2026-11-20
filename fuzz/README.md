# GeneralZip 读路径 Fuzzing

解析不可信输入是压缩库的核心风险面。本目录提供持续 fuzzing 的工程入口。

## 结构

- `GeneralZip.Fuzz/` — SharpFuzz harness（libFuzzer/AFL 桥接），fuzz 目标 = `GeneralZipReader.Open(stream)` + 全条目流式读取。
- `tests/GeneralZip.Tests/RobustnessTests.cs` — 无需 fuzz 工具链的 CI 健壮性回归：随机字节 / 截断归档 / 位翻转变异，断言只允许归档类异常。

## 本地运行（AFL++）

```bash
# 1. 构建 harness（需 libFuzzer 运行时；.NET 8 SDK 自带 shadow copy 方式不再适用，
#    参考 SharpFuzz 文档：https://github.com/Metalnem/sharpfuzz）
dotnet publish fuzz/GeneralZip.Fuzz -c Release -f net8.0 -o fuzz/out

# 2. 注入路径覆盖插桩
sharpfuzz fuzz/out/GeneralZip.dll

# 3. AFL++ 驱动（SharpFuzz 使用 AFL 的共享内存接口）
afl-fuzz -i corpus -o findings -- dotnet fuzz/out/GeneralZip.Fuzz.dll

# 4. 复现某个 finding
dotnet fuzz/out/GeneralZip.Fuzz.dll findings/crash-<id>
```

## 判定规则

fuzz 目标只捕获"预期内拒识"：`ArchiveException` 家族、`IOException`、`NotSupportedException`、
`ArgumentException`、`InvalidOperationException`、`CryptographicException`。
其它任何异常（含本应吞掉的越界/断言/原生崩溃）都是 fuzz 发现，最小化输入后提 issue 修复并回填
`RobustnessTests.cs` 固定用例。
