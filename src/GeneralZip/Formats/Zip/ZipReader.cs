using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using GeneralZip;
using GeneralZip.Abstractions;
using GeneralZip.Internal;

namespace GeneralZip.Formats.Zip;

/// <summary>
/// ZIP 读取器。打开时解析中央目录（含 Zip64），条目数据惰性解压。
/// 加密条目经 IEncryptionProvider（extra field 匹配）或 ZipCrypto（标志位匹配）挂接。
/// </summary>
internal sealed class ZipReader : IArchiveReader
{
    private readonly Stream _stream;
    private readonly bool _ownsStream;
    private readonly ArchiveOpenOptions _options;
    private readonly List<ZipEntryView> _entries = new();
    private readonly EncryptionRegistry _encryption;

    public ZipReader(Stream stream, ArchiveOpenOptions options, bool ownsStream, EncryptionRegistry? encryption = null)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _ownsStream = ownsStream;
        _encryption = encryption ?? EncryptionRegistry.Default;

        if (!stream.CanSeek)
        {
            throw new NotSupportedException("ZIP 读取需要可寻址流（ZIP 格式能力位不含顺序流读取）");
        }

        var (centrals, _) = ZipStructure.ReadCentralDirectory(stream);
        foreach (var central in centrals)
        {
            var fullName = NormalizeName(central.DecodeName(_options.EntryNameEncoding));
            _entries.Add(new ZipEntryView(central, fullName, ResolveEncryptionAlgorithm(central)));
        }

        IsEncrypted = ResolveIsEncrypted();
    }

    public ArchiveFormatInfo Format { get; } = new(
        "ZIP",
        new[] { ".zip" },
        FormatCapabilities.Read | FormatCapabilities.Write | FormatCapabilities.EncryptedRead |
        FormatCapabilities.EncryptedWrite | FormatCapabilities.SeekableRead | FormatCapabilities.Append,
        "自研 ZIP 引擎：Store/Deflate/Zip64 + ZipCrypto/WinZip AES/SM4-GM");

    public IReadOnlyList<IArchiveEntry> Entries => _entries;

    public bool IsEncrypted { get; }

    public Stream OpenEntryStream(IArchiveEntry entry)
    {
        if (entry is not ZipEntryView view)
        {
            throw new ArgumentException("条目不属于当前归档（须来自 Entries）", nameof(entry));
        }

        return OpenEntryStreamCore(view);
    }

    public void CopyEntryTo(IArchiveEntry entry, Stream destination, CancellationToken cancellationToken)
    {
        using var source = OpenEntryStream(entry);
        var buffer = new byte[81920];
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            destination.Write(buffer, 0, read);
        }
    }

    private Stream OpenEntryStreamCore(ZipEntryView view)
    {
        var central = view.Central;

        // 1) 定位数据起点
        var (localFlags, _, dataOffset) = ZipStructure.ReadLocalHeader(_stream, central);
        var cipherSize = central.CompressedSize;
        if (cipherSize < 0)
        {
            cipherSize = Math.Max(0, _stream.Length - dataOffset);
        }

        var source = (Stream)new PartialStream(_stream, dataOffset, cipherSize);

        // 2) 加密层（同一 extra field 可能注册多个提供者——如 AES-128/256，逐候选尝试）
        if ((central.Flags & ZipConstants.FlagEncrypted) != 0)
        {
            var candidates = BuildEncryptionCandidates(central, out var unknownAlgorithm);
            if (candidates.Count == 0)
            {
                throw unknownAlgorithm == null
                    ? new PasswordRequiredException(view.FullName)
                    : new UnsupportedFormatException($"不支持的加密算法：{unknownAlgorithm}", view.FullName);
            }

            var password = GetPassword(view.FullName);
            if (password == null)
            {
                throw new PasswordRequiredException(view.FullName);
            }

            Exception? lastFailure = null;
            var decrypted = false;
            foreach (var provider in candidates)
            {
                var readContext = new EncryptionReadContext(password, view.FullName, provider.Parameters, cipherSize);
                try
                {
                    source = provider.Provider.OpenRead(source, readContext);
                    decrypted = true;
                    break;
                }
                catch (UnsupportedFormatException ex)
                {
                    lastFailure = ex; // 强度/参数不匹配 → 换下一候选
                }
                catch (ArchiveCorruptedException ex) when (candidates.Count > 1)
                {
                    lastFailure = ex;
                }
            }

            if (!decrypted)
            {
                if (lastFailure is UnsupportedFormatException)
                {
                    throw lastFailure;
                }

                // 全部候选失败（单候选的口令/完整性异常在此原样抛出）
                if (candidates.Count == 1)
                {
                    throw new ArchiveException("解密失败", view.FullName, lastFailure);
                }

                throw lastFailure ?? new InvalidPasswordException(view.FullName);
            }
        }

        // 3) 解压层（加密条目的真实方法藏在 extra field，主方法=99）
        var effectiveMethod = central.Method;
        if (effectiveMethod == ZipConstants.MethodEncryptedMarker)
        {
            effectiveMethod = ExtractRealMethod(central);
        }

        Stream decoded = effectiveMethod switch
        {
            ZipConstants.MethodStore => source,
            ZipConstants.MethodDeflate => new DeflateStream(source, CompressionMode.Decompress, leaveOpen: true),
            _ => throw new UnsupportedFormatException($"不支持的 ZIP 压缩方法：{effectiveMethod}", view.FullName),
        };

        // 4) CRC 校验（加密条目的 CRC 恒 0，由 HMAC 保证完整性；ZipCrypto 的 CRC 失败提示口令/损坏两种可能）
        uint? expectedCrc = null;
        if ((central.Flags & ZipConstants.FlagEncrypted) == 0 || central.Crc32 != 0)
        {
            expectedCrc = central.Crc32;
        }

        return new CrcCheckStream(decoded, expectedCrc, view.FullName, central.UncompressedSize >= 0 ? central.UncompressedSize : null);
    }

    private string? ResolveEncryptionAlgorithm(ZipCentralEntry central)
    {
        if ((central.Flags & ZipConstants.FlagEncrypted) == 0)
        {
            return null;
        }

        var provider = FindProviderByExtra(central);
        return provider?.AlgorithmId ?? "ZipCrypto";
    }

    private bool ResolveIsEncrypted()
    {
        foreach (var e in _entries)
        {
            if (e.IsEncrypted) return true;
        }

        return false;
    }

    private IEncryptionProvider? FindProviderByExtra(ZipCentralEntry central)
    {
        var pos = 0;
        while (pos + 4 <= central.Extra.Length)
        {
            var id = Le.U16(central.Extra, pos);
            var size = Le.U16(central.Extra, pos + 2);
            pos += 4;
            var provider = _encryption.FindByZipExtraFieldId(id);
            if (provider != null && provider.SupportsRead)
            {
                return provider;
            }

            pos += size;
        }

        return null;
    }

    private sealed class EncryptionCandidate
    {
        public EncryptionCandidate(IEncryptionProvider provider, IReadOnlyDictionary<string, object?> parameters)
        {
            Provider = provider;
            Parameters = parameters;
        }

        public IEncryptionProvider Provider { get; }
        public IReadOnlyDictionary<string, object?> Parameters { get; }
    }

    private List<EncryptionCandidate> BuildEncryptionCandidates(ZipCentralEntry central, out string? unknownAlgorithm)
    {
        unknownAlgorithm = null;
        var candidates = new List<EncryptionCandidate>();

        // 1) extra field 指明的算法族（WinZip AES / SM4-GM），同族多提供者逐个尝试
        var pos = 0;
        while (pos + 4 <= central.Extra.Length)
        {
            var id = Le.U16(central.Extra, pos);
            var size = Le.U16(central.Extra, pos + 2);
            var data = new byte[size];
            Buffer.BlockCopy(central.Extra, pos + 4, data, 0, size);
            pos += 4 + size;

            foreach (var provider in _encryption.FindAllByZipExtraFieldId(id))
            {
                if (provider.SupportsRead)
                {
                    candidates.Add(new EncryptionCandidate(
                        provider,
                        new Dictionary<string, object?> { ["ZipExtraFieldData"] = data }));
                }
            }

            if (id == 0x9901 && candidates.Count == 0)
            {
                unknownAlgorithm = $"WinZip AES（无已注册提供者处理 0x{id:X4}）";
            }
        }

        if (candidates.Count > 0)
        {
            return candidates;
        }

        // 2) 标志位指明的 ZipCrypto
        if ((central.Flags & ZipConstants.FlagEncrypted) != 0)
        {
            var zipCrypto = _encryption.Find("ZipCrypto");
            if (zipCrypto == null || !zipCrypto.SupportsRead)
            {
                unknownAlgorithm = "ZipCrypto";
                return candidates;
            }

            var checkByte = central.UsesDataDescriptor
                ? (byte)((central.DosTime >> 8) & 0xFF)
                : (byte)((central.Crc32 >> 24) & 0xFF);
            var checkByteAlt = central.UsesDataDescriptor
                ? (byte)((central.Crc32 >> 24) & 0xFF)
                : (byte)((central.DosTime >> 8) & 0xFF);

            candidates.Add(new EncryptionCandidate(zipCrypto, new Dictionary<string, object?>
            {
                ["ZipCryptoCheckByte"] = checkByte,
                ["ZipCryptoCheckByteAlt"] = checkByteAlt,
                ["ZipCryptoHeaderSize"] = 12,
            }));
        }

        return candidates;
    }

    private static ushort ExtractRealMethod(ZipCentralEntry central)
    {
        // 真实压缩方法藏在加密 extra field 尾部（0x9901 偏移 5，0x4D53 末 2 字节）
        var pos = 0;
        while (pos + 4 <= central.Extra.Length)
        {
            var id = Le.U16(central.Extra, pos);
            var size = Le.U16(central.Extra, pos + 2);
            var dataStart = pos + 4;
            if (id == 0x9901 && size >= 7)
            {
                return Le.U16(central.Extra, dataStart + 5);
            }

            if (id == 0x4D53 && size >= 2)
            {
                return Le.U16(central.Extra, dataStart + size - 2);
            }

            pos += 4 + size;
        }

        throw new ArchiveCorruptedException("方法 99（加密）条目缺少真实压缩方法信息");
    }

    private string? GetPassword(string entryName)
    {
        return _options.PasswordProvider?.GetPassword(new PasswordRequest(PasswordScope.SingleEntry, entryName, 1, 1))
               ?? _options.Password;
    }

    private static string NormalizeName(string name)
    {
        var n = name.Replace('\\', '/');
        while (n.StartsWith("/", StringComparison.Ordinal))
        {
            n = n.Substring(1);
        }

        return n;
    }

    public void Dispose()
    {
        if (_ownsStream)
        {
            _stream.Dispose();
        }
    }
}
