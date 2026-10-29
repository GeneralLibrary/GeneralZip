# GeneralZip

<div align="right">

[**English**](README.md) | [中文](README.zh-CN.md)

</div>

A cross-format, encryption-capable (including Chinese national cryptography standards), event-driven compression library for .NET.

```csharp
// Idempotent bootstrap + one-liners: compress / extract / test
GeneralZip.Initialize();
await GeneralZip.CompressAsync(@"C:\data", @"D:\backup.zip",
    o => { o.Level = CompressionLevelChoice.Optimal;
           o.EncryptionAlgorithm = "SM4-GM";       // Chinese national crypto (SM4)
           o.Password = "a-strong-password-from-your-vault"; });

await GeneralZip.ExtractAsync(@"D:\backup.zip", @"D:\restore");

// Event-driven + streaming
using var reader = ArchiveReader.Open(@"D:\arch.7z", o => o.Password = "...", r =>
{
    r.PasswordRequired += (_, e) => e.Password = AskUser();   // interactive password
    r.OverallProgress  += (_, p) => ShowProgress(p);          // progress / speed / ETA
});
await reader.ExtractToDirectoryAsync(@"D:\out");
```

> The bootstrap class shares the component name (`class GeneralZip` inside `namespace GeneralZip`).
> Recommended usage: `using GeneralZip;` + `using static GeneralZip.GeneralZip;` so you can call
> `Initialize()` / `CompressAsync()` etc. unqualified.

## Features

| Capability | Details |
|---|---|
| Broad format support | ZIP / 7z / RAR / TAR / TAR.GZ / TAR.BZ2 / GZ / BZ2 / XZ / Zstd / LZ4 |
| Encryption matrix | ZipCrypto, **WinZip AES-128/256** (universal interop), **SM4-GM** (Chinese national standard, custom spec), 7z AES-256, RAR (read-only) |
| SM (Guomi) scheme | SM3-PBKDF2 key derivation + SM4-CTR + SM3-HMAC (Encrypt-then-MAC); binary spec in [docs/CRYPTO-SPEC.md](docs/CRYPTO-SPEC.md) |
| Event system | Per-entry progress, overall progress (speed/ETA), `PasswordRequired` negotiation (retry counting/caching), `OverwriteQuery`, `ErrorReport` (retry/skip/abort) |
| Developer-friendly | One-liner facade + streaming API, full `CancellationToken`, `IProgress<T>`, dual target `netstandard2.0` + `net8.0` |
| Pluggable | `IArchiveFormat` / `IEncryptionProvider` are both third-party extensible |
| Secure defaults | zip-slip protection, ZipCrypto writing disabled by default (explicit opt-in), HMAC tamper rejection, fast-fail on wrong passwords, constant-time comparison |

## Format & Encryption Matrix

| Format | Read | Write | Encrypted Read | Encrypted Write |
|---|---|---|---|---|
| ZIP (Store/Deflate/Zip64) | ✓ | ✓ | ZipCrypto / WinZip AES / **SM4-GM** | same |
| 7z (LZMA2) | ✓ | ✓ | AES-256 | AES-256 |
| RAR4/RAR5 | ✓ | — (proprietary) | ✓ password | — |
| TAR / TAR.GZ | ✓ | ✓ | — | — |
| GZ | ✓ (.NET built-in) | ✓ (.NET built-in) | — | — |
| BZ2 / XZ / ZSTD / LZ4 | ✓ (native core) | ✓ (native core) | — | — |

> 7z/RAR and BZ2/XZ/ZSTD/LZ4 are provided by the **Rust native core** (all pure-Rust implementations).
> When the core is missing the library degrades gracefully: ZIP/TAR/TAR.GZ/GZ (pure managed) and all
> ZIP-family encryption remain fully functional.

## Build & Test

```powershell
.\build\build.ps1              # Rust native core + managed + all tests
.\build\build.ps1 -SkipNative  # managed only (7z/RAR/xz-write unavailable)
```

Prerequisites:
- .NET SDK 8.0+ (multi-targets netstandard2.0 + net8.0)
- Rust (native core only): GNU toolchain recommended; CN mirror:
  ```powershell
  $env:RUSTUP_DIST_SERVER="https://rsproxy.cn"; $env:RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"
  rustup-init.exe -y --default-toolchain stable-x86_64-pc-windows-gnu --profile minimal
  ```
- RAR support (`rar` cargo feature): additionally requires a C++ toolchain (MSVC); off by default

Deploying the native core (app side): place `generalzip_native.dll/.so/.dylib` in the app directory,
under `runtimes/<RID>/native/`, or set the `GENERALZIP_NATIVE` environment variable; call
`GeneralZipNative.Initialize()` once at startup.

## Usage Examples

Fully runnable examples in [samples/GeneralZip.Samples](samples/GeneralZip.Samples/Program.cs):
one-liner compression, SM4 encrypted round-trip, event-driven flows (progress/password/error policies),
7z encrypted read/write, xz codec, integrity testing.

### API Quick Reference

```csharp
// Open + automatic format detection (magic bytes first)
using var reader = ArchiveReader.Open(path);
foreach (var entry in reader.Entries) { /* FullName/Size/IsEncrypted/... */ }
using Stream s = reader.OpenEntryStream(entry);        // lazy decompression stream

// Extraction policies
var result = reader.ExtractToDirectory(dest, new ExtractionOptions {
    OverwritePolicy = OverwritePolicy.Ask,             // raises OverwriteQuery
    ErrorPolicy     = ErrorPolicy.RaiseEvent,          // raises ErrorReport
    Filter          = e => e.FullName.EndsWith(".pdf"),
});

// Writing (sequential API; non-seekable streams supported)
using var writer = ArchiveWriter.CreateNew(outPath, o =>
{
    o.Level = CompressionLevelChoice.SmallestSize;
    o.EncryptionAlgorithm = "WinZipAES256";
    o.Password = password;
});
writer.AddFile(@"C:\a.pdf", "docs/a.pdf");
writer.AddDirectory(@"C:\photos", "photos");
await writer.FinishAsync();                            // auto-finalized on Dispose if not finished

// Extensibility: register custom formats / encryption algorithms
GeneralZip.Registry.Register(new MyArchiveFormat());
GeneralZip.Encryption.Register(new MyEncryptionProvider());
```

## Sample Files

[samples/fixtures/](samples/fixtures/README.md) ships sample archives for **every supported format**:
10 plaintext formats (ZIP / 7z / TAR / TAR.GZ / TAR.BZ2 / GZ / BZ2 / XZ / ZSTD / LZ4)
+ 4 encrypted variants (SM4-GM / WinZip AES-256 / ZipCrypto / 7z AES-256),
with the public demo password and plaintext SHA-256 checksums. They also serve as cross-version
compatibility anchors (verified automatically in `tests/`).

## Architecture Docs & Benchmarks

> 🌐 Docs language (i18n): the in-depth design documents are currently Chinese-only; this English
> README covers features and usage.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layered architecture, interface contracts, event protocol, Rust FFI design, extension guide (Chinese)
- [docs/CRYPTO-SPEC.md](docs/CRYPTO-SPEC.md) — binary specification of the SM4-GM encrypted ZIP container for third-party interop (Chinese)
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — throughput benchmarks for all formats (including encryption overhead), generated by `samples/GeneralZip.Bench`
- [samples/fixtures/](samples/fixtures/README.md) — encrypted sample archives (SM4-GM / WinZip AES-256 / ZipCrypto / 7z AES-256) with the public demo password and plaintext SHA-256 checksums; also cross-version compatibility anchors (verified automatically in `tests/`)

## Dependencies & License

**The core package has zero third-party NuGet dependencies** — no third-party NuGet is referenced
other than Microsoft-maintained packages:

| Component | Purpose | Maintainer |
|---|---|---|
| System.IO.Compression / System.Security.Cryptography | Deflate, GZip container, AES, SHA1, PBKDF2-SHA1 | Microsoft |
| SM3 / SM4 / HMAC-SM3 / PBKDF2-SM3 / TAR(ustar) / CRC32 | Pure C# implementations in this project (locked by GB/T standard vectors) | GeneralZip |
| Microsoft.Bcl.AsyncInterfaces | netstandard2.0 async API polyfill | Microsoft |
| Rust core: sevenz-rust2 / lzma-rs / lzma_rust2 / bzip2(libbz2-rs) / lz4_flex / rust-zstd | 7z, xz, bzip2, lz4, zstd codecs | Rust community (per upstream) |

Non-compression cryptographic primitives (SM3/SM4/SM-HMAC) are pure C# implementations locked by
GB/T standard vectors; compression codecs (bzip2/xz/zstd/lz4/7z) are concentrated in the Rust native
core, all pure-Rust (no C toolchain required).

This project's code is MIT licensed.

## Known Limitations (v1.1)

- RAR is read-only (the WinRAR compression algorithm is proprietary; no compliant implementation can create it)
- 7z archives do not support appending to existing archives (each write creates a whole new archive)
- SM4-GM is a custom specification (ZIP has no official SM4 standard); interop is limited to this
  component and third parties implementing the same spec
- **BZ2 / XZ / ZSTD / LZ4 codecs require the native core**: without it these formats are unavailable
  (ZIP/TAR/TAR.GZ/GZ/7z/RAR are unaffected); GZip uses the .NET built-in implementation and is always available
- Native zstd compression is a one-shot in-memory API (compressing large files uses memory equal to
  the source size); xz/lz4/bzip2 are streaming
- Reading encrypted 7z / large archives extracts each entry to a temp file (random-access semantics;
  a batched path for sequential bulk extraction is planned)
