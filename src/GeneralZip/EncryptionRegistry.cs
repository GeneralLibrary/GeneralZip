using System;
using System.Collections.Generic;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// 加密算法注册表。内置提供者预注册；第三方算法经 <see cref="Register"/> 注入后即可被所有格式使用。
/// 线程安全。
/// </summary>
public sealed class EncryptionRegistry
{
    private readonly object _lock = new();
    private readonly Dictionary<string, IEncryptionProvider> _byId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<ushort, List<IEncryptionProvider>> _byZipExtraField = new();

    public EncryptionRegistry() { }

    internal EncryptionRegistry(bool populateBuiltins)
    {
        if (populateBuiltins)
        {
            Register(new Cryptography.ZipCryptoProvider());
            Register(new Cryptography.WinZipAesProvider(Cryptography.AesKeyStrength.Bits128));
            Register(new Cryptography.WinZipAesProvider(Cryptography.AesKeyStrength.Bits256));
            Register(new Cryptography.Sm4GmProvider());
        }
    }

    public static EncryptionRegistry Default { get; } = new(populateBuiltins: true);

    /// <summary>注册提供者；同 AlgorithmId 重复注册将覆盖。</summary>
    public void Register(IEncryptionProvider provider)
    {
        if (provider == null) throw new ArgumentNullException(nameof(provider));

        lock (_lock)
        {
            _byId[provider.AlgorithmId] = provider;
            foreach (var id in provider.ZipExtraFieldIds)
            {
                if (!_byZipExtraField.TryGetValue(id, out var list))
                {
                    list = new List<IEncryptionProvider>();
                    _byZipExtraField[id] = list;
                }

                // 同一 extra field 可由多个提供者竞争（如 AES-128/256）；按注册逆序尝试
                list.RemoveAll(p => p.AlgorithmId == provider.AlgorithmId);
                list.Add(provider);
            }
        }
    }

    public IEncryptionProvider? Find(string algorithmId)
    {
        lock (_lock)
        {
            return _byId.TryGetValue(algorithmId, out var p) ? p : null;
        }
    }

    /// <summary>按 ZIP extra field 标识查找全部候选（注册逆序 = 新注册优先）。</summary>
    public IReadOnlyList<IEncryptionProvider> FindAllByZipExtraFieldId(ushort extraFieldId)
    {
        lock (_lock)
        {
            if (!_byZipExtraField.TryGetValue(extraFieldId, out var list))
            {
                return Array.Empty<IEncryptionProvider>();
            }

            var copy = new List<IEncryptionProvider>(list);
            copy.Reverse();
            return copy;
        }
    }

    /// <summary>按 ZIP extra field 标识查找首个候选（兼容便捷方法）。</summary>
    public IEncryptionProvider? FindByZipExtraFieldId(ushort extraFieldId)
    {
        var all = FindAllByZipExtraFieldId(extraFieldId);
        return all.Count > 0 ? all[0] : null;
    }

    public IReadOnlyList<IEncryptionProvider> Snapshot()
    {
        lock (_lock)
        {
            return new List<IEncryptionProvider>(_byId.Values);
        }
    }
}
