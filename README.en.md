<div align="center">

# GeneralZip

**A cross-format, encryption-capable (SM4/Guomi included), event-driven compression library for .NET**

[![CI](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/ci.yml/badge.svg)](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/ci.yml)
[![Release](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/release.yml/badge.svg)](https://github.com/GeneralLibrary/GeneralZip/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-netstandard2.0%20%7C%20net8.0-blueviolet)](https://learn.microsoft.com/dotnet/standard/net-standard)

[**English**](README.md) | [中文](README.zh-CN.md)

</div>

---

## Why GeneralZip?

- **One API, many formats** — ZIP, 7z, RAR, TAR, GZ, BZ2, XZ, Zstd, LZ4 with automatic magic-byte detection. No more "which library do I need for this file?"
- **Encryption done right** — WinZip AES for universal interop, plus **SM4-GM** (Chinese national cryptography) as a documented custom ZIP extension, all behind one `EncryptionAlgorithm` switch.
- **Built for apps, not just scripts** — full event system (progress, interactive password prompts, overwrite decisions, error policies), `CancellationToken` everywhere, `IProgress<T>` support.
- **Zero third-party NuGet dependencies in the core** — cryptographic primitives (SM3/SM4) and the TAR container are pure C# implementations validated against GB/T standard test vectors; native codecs (7z/bzip2/xz/zstd/lz4) live in an optional Rust native core, all pure Rust.

## Installation

```
dotnet add package GeneralZip          # core (pure managed)
dotnet add package GeneralZip.Native   # optional: 7z/RAR/BZ2/XZ/ZSTD/LZ4 via Rust core
```

Targets `netstandard2.0` and `net8.0`.

> The native package embeds prebuilt cores for win-x64, linux-x64, linux-musl-x64, osx-x64 and osx-arm64.
> Call `GeneralZipNative.Initialize()` once at startup — if the core is missing for your platform,
> 7z/RAR and those codecs degrade gracefully; everything else keeps working.

## Quick Start

### Compress / extract in one line

```csharp
using GeneralZip;

GeneralZip.Initialize();  // idempotent bootstrap

// Directory → archive (format is chosen by the file extension)
await GeneralZip.CompressAsync(@"C:\data", @"D:\backup.zip");

// Archive → directory
var result = await GeneralZip.ExtractAsync(@"D:\backup.zip", @"D:\restore");
Console.WriteLine($"Extracted {result.ProcessedCount} entries, {result.FailedCount} failed");
```

### Encrypted archives

```csharp
using GeneralZip;
using GeneralZip.Abstractions;

// Write: SM4-GM (Chinese national crypto) — see docs/CRYPTO-SPEC.md
await GeneralZip.CompressAsync(@"C:\data", @"D:\backup.zip", o =>
{
    o.Level = CompressionLevelChoice.Optimal;
    o.EncryptionAlgorithm = "SM4-GM";          // or "WinZipAES256" for universal interop
    o.Password = password;                     // get it from your secret store, never hard-code
    o.KdfIterations = 10_000;                  // SM3-PBKDF2 rounds
});

// Read: wrong passwords fail fast (per-entry verifier), no silent corruption
using var reader = ArchiveReader.Open(@"D:\backup.zip", o => o.Password = password);
var entry = reader.Entries[0];
using var stream = reader.OpenEntryStream(entry);   // lazy decrypt + decompress stream
```

### Streaming API with events

```csharp
using GeneralZip;
using GeneralZip.Abstractions;

// Create an archive with progress reporting
using var writer = ArchiveWriter.CreateNew(@"D:\photos.zip", o =>
{
    o.Level = CompressionLevelChoice.SmallestSize;
    o.Progress = new Progress<ArchiveProgress>(p =>
        Console.Write($"\r{p.Percent:F0}% {p.CurrentEntry}"));
});
writer.AddFile(@"C:\a.pdf", "docs/a.pdf");
await writer.AddDirectoryAsync(@"C:\photos", "photos");
await writer.FinishAsync();     // auto-finalized on Dispose too
```

```csharp
// Extract with interactive password, overwrite and error handling
using var reader = ArchiveReader.Open(archivePath, configure: null, r =>
{
    // For whole-archive formats (e.g. 7z header encryption) subscribe here —
    // the password may be needed during Open itself.
    r.PasswordRequired += (_, e) =>
    {
        e.Password = PromptPassword(e.EntryName, e.Attempt);   // your UI logic
        if (e.Attempt >= 3) e.Cancel = true;                   // give up after 3 tries
    };
    r.OverallProgress += (_, p) => UpdateProgressBar(p.Percent, p.Eta);
});

var result = reader.ExtractToDirectory(@"D:\out", new ExtractionOptions
{
    OverwritePolicy = OverwritePolicy.Ask,      // raises reader.OverwriteQuery
    ErrorPolicy = ErrorPolicy.RaiseEvent,       // raises reader.ErrorReport (retry/skip/abort)
    Filter = e => e.FullName.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase),
});
```

### Integrity testing

```csharp
var test = ArchiveReader.Open(path).TestAll();
Console.WriteLine(test.Success ? "OK" : $"{test.FailedCount} entries failed");
```

### Format detection & extensibility

```csharp
var info = GeneralZip.DetectFormat(mysteryFile);    // magic bytes first, extension fallback
Console.WriteLine(info?.Name);                      // "ZIP", "7Z", "TAR.GZ", ...

// Register a custom format or encryption algorithm
GeneralZip.Registry.Register(new MyArchiveFormat());
GeneralZip.Encryption.Register(new MyEncryptionProvider());
```

## Format & Encryption Matrix

| Format | Read | Write | Encrypted Read | Encrypted Write |
|---|:---:|:---:|:---:|:---:|
| ZIP (Store/Deflate/Zip64) | ✓ | ✓ | ZipCrypto / WinZip AES / **SM4-GM** | ✓ |
| 7z (LZMA2) | ✓ | ✓ | AES-256 | AES-256 |
| RAR4/RAR5 | ✓ | — (proprietary) | ✓ password | — |
| TAR / TAR.GZ | ✓ | ✓ | — | — |
| GZ | ✓ (.NET built-in) | ✓ (.NET built-in) | — | — |
| BZ2 / XZ / ZSTD / LZ4 | ✓ (native core) | ✓ (native core) | — | — |

> 7z/RAR and BZ2/XZ/ZSTD/LZ4 are provided by the **Rust native core** (all pure-Rust crates).
> When the core is missing, the library degrades gracefully: ZIP/TAR/TAR.GZ/GZ (pure managed)
> and all ZIP-family encryption are unaffected.

## Building from Source

```powershell
.\build\build.ps1              # Rust native core + managed build + all tests
.\build\build.ps1 -SkipNative  # managed only (7z/RAR and the native codecs unavailable)
```

Prerequisites:
- .NET SDK 8.0+
- Rust (native core only) — GNU toolchain on Windows:
  ```powershell
  rustup-init.exe -y --default-toolchain stable-x86_64-pc-windows-gnu --profile minimal
  ```
- RAR support (`rar` cargo feature): additionally requires MSVC; off by default

### Deploying the native core manually

Place `generalzip_native.dll/.so/.dylib` in one of:
1. the application directory,
2. `runtimes/<RID>/native/` under the app directory,
3. any path referenced by the `GENERALZIP_NATIVE` environment variable,

then call `GeneralZipNative.Initialize()` once at startup.

## Sample Files

[samples/fixtures/](samples/fixtures/README.md) ships sample archives for **every supported format**
(10 plaintext + 4 encrypted variants) with the public demo password and plaintext SHA-256 checksums.
These are also cross-version compatibility anchors verified by the test suite.

## Benchmarks

Throughput numbers for all formats (including per-algorithm encryption overhead), measured by
[samples/GeneralZip.Bench](samples/GeneralZip.Bench/Program.cs): [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Documentation

| Document | Content |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layered architecture, interface contracts, event protocol, Rust FFI design (Chinese) |
| [docs/CRYPTO-SPEC.md](docs/CRYPTO-SPEC.md) | Binary spec of the SM4-GM encrypted ZIP container for third-party interop (Chinese) |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Full-format performance data (Chinese) |
| [samples/](samples/) | Runnable samples: basic usage, events, benchmarks, fixture generator |

## Project Layout

```
src/GeneralZip/           Core library (pure managed, zero third-party NuGet)
src/GeneralZip.Native/    Rust core bindings (P/Invoke, graceful degradation)
native/generalzip-native/ Rust cdylib: 7z/bzip2/xz/zstd/lz4 codecs (C ABI)
native/dlltool-shim-rs/   Build helper for windows-gnu raw-dylib imports
tests/                    73 tests: standard vectors, interop oracle, events, fixtures
samples/                  Samples + sample archives (fixtures)
build/                    One-shot build script
```

## Known Limitations

- RAR is **read-only** — the compression algorithm is proprietary; no compliant implementation can create RAR archives.
- 7z archives cannot be appended to (each write produces a whole new archive).
- SM4-GM is a custom specification (ZIP has no official SM4 standard); interop is limited to this library and third parties implementing the same spec.
- BZ2/XZ/ZSTD/LZ4 require the native core; GZip is always available (pure managed).
- Native zstd compression is a one-shot in-memory API; xz/lz4/bzip2 stream.

## Contributing & License

Issues and PRs are welcome. Please run `build\build.ps1` and make sure all tests pass before submitting.

Released under the [MIT License](LICENSE).
