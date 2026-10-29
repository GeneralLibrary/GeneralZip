using System;
using System.Collections.Generic;
using GeneralZip.Abstractions;

namespace GeneralZip;

/// <summary>
/// 口令闸门：预置口令 / 事件应答 / 动态提供者 / 会话级缓存 的统一入口。
/// 尝试计数只对"真实外部询问"累计（缓存命中不计），口令失效经 <see cref="Invalidate"/> 后重新询问。
/// </summary>
internal sealed class PasswordGate : IPasswordProvider
{
    private readonly string? _preset;
    private readonly IPasswordProvider? _external;
    private readonly Func<EventHandler<PasswordRequiredEventArgs>?> _handlerAccessor;
    private readonly int _maxAttempts;
    private readonly bool _propagateEventExceptions;
    private readonly Dictionary<string, string> _cache = new(StringComparer.Ordinal);
    private readonly HashSet<string> _presetBurned = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _askCounts = new(StringComparer.Ordinal);
    private string? _lastUsed; // 最近一次提供的口令：新条目首次询问前先行尝试，避免整包加密场景逐条目打扰

    public PasswordGate(
        ArchiveOpenOptions options,
        Func<EventHandler<PasswordRequiredEventArgs>?> handlerAccessor)
    {
        _preset = options.Password;
        _external = options.PasswordProvider;
        _handlerAccessor = handlerAccessor;
        _maxAttempts = Math.Max(1, options.MaxPasswordAttempts);
        _propagateEventExceptions = false;
    }

    /// <summary>口令错误后由门面调用：作废缓存并禁用该键的预置口令，下次询问重新走向外部。</summary>
    public void Invalidate(string? cacheKey)
    {
        var key = cacheKey ?? string.Empty;
        _cache.Remove(key);
        _presetBurned.Add(key);
        // 最近使用口令已证明对该包无效：一并清除，避免其余条目无限重试
        _lastUsed = null;
    }

    /// <summary>打开后直接补充口令（等价于重新预置，立即进入缓存）。</summary>
    public void SupplyOverride(string? cacheKey, string password)
    {
        _cache[cacheKey ?? string.Empty] = password;
    }

    /// <summary>
    /// 是否还有再询问通道（预置未失效 / 提供者 / 事件处理器 且未超次数）。
    /// 门面据此在 ErrorPolicy=Throw 下仍进行口令重询问（交互协议独立于错误策略）。
    /// </summary>
    public bool CanReask(string? cacheKey)
    {
        var key = cacheKey ?? string.Empty;
        if (_preset != null && !_presetBurned.Contains(key))
        {
            return true;
        }

        if (_askCounts.TryGetValue(key, out var n) && n >= _maxAttempts)
        {
            return false;
        }

        return _external != null || _handlerAccessor() != null;
    }

    public string? GetPassword(PasswordRequest request)
    {
        var key = request.EntryName ?? string.Empty;

        // 1) 会话缓存（含 SupplyOverride 种入值）
        if (_cache.TryGetValue(key, out var cached))
        {
            return cached;
        }

        // 2) 预置口令（每个键只直用一次；失效后不再重放）
        if (_preset != null && !_presetBurned.Contains(key))
        {
            _cache[key] = _preset;
            _lastUsed = _preset;
            return _preset;
        }

        // 3) 最近使用口令（整包同一口令的常见场景；失败由门面 Invalidate 后正常走向外部）
        if (_lastUsed != null)
        {
            _cache[key] = _lastUsed;
            return _lastUsed;
        }

        // 4) 外部询问（提供者或事件），计数防死循环
        var askCount = _askCounts.TryGetValue(key, out var n) ? n + 1 : 1;
        _askCounts[key] = askCount;
        if (askCount > _maxAttempts)
        {
            return null;
        }

        var normalized = new PasswordRequest(request.Scope, request.EntryName, askCount, _maxAttempts);

        string? answer;
        if (_external != null)
        {
            answer = _external.GetPassword(normalized);
        }
        else
        {
            var handler = _handlerAccessor();
            if (handler == null)
            {
                return null;
            }

            var args = new PasswordRequiredEventArgs(normalized);
            try
            {
                handler(this, args);
            }
            catch (Exception) when (!_propagateEventExceptions)
            {
                return null; // 事件内异常隔离：视为放弃
            }

            answer = args.HasAnswer ? args.Password : null;
        }

        if (answer == null)
        {
            return null;
        }

        _cache[key] = answer;
        _lastUsed = answer;
        return answer;
    }
}
