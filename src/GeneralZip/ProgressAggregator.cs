using System;
using System.Diagnostics;
using System.Threading;

namespace GeneralZip;

/// <summary>
/// 进度聚合器：条目/字节两级计数 → 节流后的全局 <see cref="ArchiveProgress"/>。
/// 节流策略：距上次投递 ≥50ms 或百分比变化 ≥0.5 或条目边界，三者满足其一才投递。
/// 事件在操作线程内联触发；IProgress 由其自身实现封送。
/// </summary>
internal sealed class ProgressAggregator
{
    private readonly IProgress<ArchiveProgress>? _sink;
    private readonly Func<EventHandler<ArchiveProgress>?>? _eventHandlerAccessor;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private long _lastTickMs;
    private double _lastPercent = -1;

    private ArchivePhase _phase;
    private long _entriesDone;
    private long? _entriesTotal;
    private long _bytesDone;
    private long? _bytesTotal;
    private string? _currentEntry;
    private long _currentBytes;
    private long? _currentTotal;

    public ProgressAggregator(
        ArchivePhase phase,
        IProgress<ArchiveProgress>? sink,
        Func<EventHandler<ArchiveProgress>?>? eventHandlerAccessor)
    {
        _phase = phase;
        _sink = sink;
        _eventHandlerAccessor = eventHandlerAccessor;
    }

    public void SetTotals(long? entriesTotal, long? bytesTotal)
    {
        _entriesTotal = entriesTotal;
        _bytesTotal = bytesTotal;
    }

    public void SwitchPhase(ArchivePhase phase, string? currentEntry = null)
    {
        _phase = phase;
        _currentEntry = currentEntry;
        _currentBytes = 0;
        _currentTotal = null;
        Emit(force: true);
    }

    public void BeginEntry(string entryName, long? entryTotal)
    {
        _currentEntry = entryName;
        _currentBytes = 0;
        _currentTotal = entryTotal;
        Emit(force: true);
    }

    /// <summary>条目内字节推进（增量）。</summary>
    public void ReportEntryBytes(long delta)
    {
        if (delta <= 0) return;
        Interlocked.Add(ref _currentBytes, delta);
        Emit(force: false);
    }

    /// <summary>条目实际总量修正（探测到确切大小后）。</summary>
    public void CorrectEntryTotal(long entryTotal)
    {
        _currentTotal = entryTotal;
    }

    public void CompleteEntry(long? actualBytes = null)
    {
        if (actualBytes.HasValue)
        {
            _bytesDone += actualBytes.Value;
        }
        else
        {
            _bytesDone += _currentTotal ?? _currentBytes;
        }

        _entriesDone++;
        _currentEntry = null;
        _currentBytes = 0;
        _currentTotal = null;
        Emit(force: true);
    }

    public void Finalize(long? finalBytes = null)
    {
        if (finalBytes.HasValue)
        {
            _bytesDone = finalBytes.Value;
        }
        Emit(force: true);
    }

    private void Emit(bool force)
    {
        var nowMs = _clock.ElapsedMilliseconds;
        var percent = ComputePercent();

        if (!force)
        {
            if (nowMs - _lastTickMs < 50) return;
            if (percent.HasValue && Math.Abs(percent.Value - _lastPercent) < 0.5) return;
        }

        _lastTickMs = nowMs;
        _lastPercent = percent ?? _lastPercent;

        double? speed = null;
        TimeSpan? eta = null;
        if (nowMs > 0)
        {
            var bps = _bytesDone * 1000.0 / nowMs;
            if (bps > 1) speed = bps;
            if (percent is > 0 and < 100)
            {
                eta = TimeSpan.FromMilliseconds((100.0 - percent.Value) / percent.Value * nowMs);
            }
        }

        var snapshot = new ArchiveProgress(
            _phase,
            _currentEntry,
            _entriesDone,
            _entriesTotal,
            _bytesDone + _currentBytes,
            _bytesTotal,
            percent,
            speed,
            eta);

        _eventHandlerAccessor?.Invoke()?.Invoke(this, snapshot);
        _sink?.Report(snapshot);
    }

    private double? ComputePercent()
    {
        // 优先：总字节已知 → 字节占比
        if (_bytesTotal is > 0)
        {
            return Math.Min(100.0, (_bytesDone + _currentBytes) * 100.0 / _bytesTotal.Value);
        }

        // 次优：条目数已知 + 条目字节占比可算 → 加权
        if (_entriesTotal is > 0 && _currentTotal is > 0)
        {
            var done = _entriesDone + Math.Min(1.0, _currentBytes * 1.0 / _currentTotal.Value);
            return Math.Min(100.0, done * 100.0 / _entriesTotal.Value);
        }

        // 再次：仅条目数
        if (_entriesTotal is > 0)
        {
            return Math.Min(100.0, _entriesDone * 100.0 / _entriesTotal.Value);
        }

        return null;
    }
}
