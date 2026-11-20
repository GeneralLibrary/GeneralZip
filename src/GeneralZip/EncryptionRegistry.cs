using System;
using System.Collections.Generic;
using System.Linq;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// KDF 提供者注册表。SM4-GM 容器按 1 字节 SpecId 选择 KDF（1=SM3-PBKDF2，2=PBKDF2-SHA256）。
/// 线程安全。
/// </summary>
public sealed class GeneralZipKdfRegistry
{
    private readonly object _lock = new();
    private readonly Dictionary<byte, IKdfProvider> _bySpecId = new();
    private readonly Dictionary<string, IKdfProvider> _byName = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>注册 KDF（同 SpecId/同名重复注册将覆盖）。</summary>
    public void Register(IKdfProvider provider)
    {
        if (provider == null) throw new ArgumentNullException(nameof(provider));

        lock (_lock)
        {
            if (_bySpecId.TryGetValue(provider.SpecId, out var bySpecId)
                && !string.Equals(bySpecId.KdfId, provider.KdfId, StringComparison.OrdinalIgnoreCase))
            {
                _byName.Remove(bySpecId.KdfId);
            }

            if (_byName.TryGetValue(provider.KdfId, out var byName)
                && byName.SpecId != provider.SpecId)
            {
                _bySpecId.Remove(byName.SpecId);
            }

            _bySpecId[provider.SpecId] = provider;
            _byName[provider.KdfId] = provider;
        }
    }

    /// <summary>按容器规范 SpecId 查找。</summary>
    public IKdfProvider? Find(byte specId)
    {
        lock (_lock)
        {
            return _bySpecId.TryGetValue(specId, out var p) ? p : null;
        }
    }

    /// <summary>按标识名查找（大小写不敏感）。</summary>
    public IKdfProvider? FindByName(string kdfId)
    {
        lock (_lock)
        {
            return _byName.TryGetValue(kdfId, out var p) ? p : null;
        }
    }

    public IReadOnlyList<IKdfProvider> Snapshot()
    {
        lock (_lock)
        {
            return new List<IKdfProvider>(_byName.Values);
        }
    }
}

/// <summary>
/// 加密算法注册表。内置提供者预注册；第三方算法经 <see cref="Register"/> 注入后即可被所有格式使用。
/// 线程安全。
/// </summary>
public sealed class GeneralZipEncryptionRegistry
{
    private readonly object _lock = new();
    private readonly Dictionary<string, IEncryptionProvider> _byId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<ushort, List<IEncryptionProvider>> _byZipExtraField = new();

    public GeneralZipEncryptionRegistry()
    {
        Kdfs = new GeneralZipKdfRegistry();
    }

    internal GeneralZipEncryptionRegistry(bool populateBuiltins)
    {
        Kdfs = new GeneralZipKdfRegistry();
        if (populateBuiltins)
        {
            Register(new Cryptography.ZipCryptoProvider());
            Register(new Cryptography.WinZipAesProvider(Cryptography.AesKeyStrength.Bits128));
            Register(new Cryptography.WinZipAesProvider(Cryptography.AesKeyStrength.Bits256));
            Register(new Cryptography.Sm4GmProvider());
            Register(new Cryptography.Sm2GmProvider());

            Kdfs.Register(new Cryptography.Pbkdf2Sm3KdfProvider());
            Kdfs.Register(new Cryptography.Pbkdf2Sha256KdfProvider());
        }
    }

    public static GeneralZipEncryptionRegistry Default { get; } = new(populateBuiltins: true);

    /// <summary>KDF 提供者注册表（SM4-GM 容器按 SpecId 选择派生函数）。</summary>
    public GeneralZipKdfRegistry Kdfs { get; }

    /// <summary>注册提供者；同 AlgorithmId 重复注册将覆盖。</summary>
    public void Register(IEncryptionProvider provider)
    {
        if (provider == null) throw new ArgumentNullException(nameof(provider));

        lock (_lock)
        {
            foreach (var id in _byZipExtraField.Keys.ToArray())
            {
                var list = _byZipExtraField[id];
                list.RemoveAll(p => string.Equals(p.AlgorithmId, provider.AlgorithmId, StringComparison.OrdinalIgnoreCase));
                if (list.Count == 0)
                {
                    _byZipExtraField.Remove(id);
                }
            }

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
