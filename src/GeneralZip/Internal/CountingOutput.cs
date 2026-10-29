using System;
using System.IO;

namespace GeneralZip.Internal;

/// <summary>写入字节计数包装（支持不可寻址底层流）。Mark/BytesSinceMark 用于分段计量。</summary>
internal sealed class CountingOutput : Stream
{
    private readonly Stream _inner;
    private long _total;
    private long _mark;

    public CountingOutput(Stream inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public long TotalBytes => _total;

    public long BytesSinceMark => _total - _mark;

    public void Mark() => _mark = _total;

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => _total;

    public override long Position
    {
        get => _total;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        _inner.Write(buffer, offset, count);
        _total += count;
    }

    public override void Flush() => _inner.Flush();

    protected override void Dispose(bool disposing)
    {
        // 不关闭底层流：生命周期由创建方管理
        base.Dispose(disposing);
    }
}
