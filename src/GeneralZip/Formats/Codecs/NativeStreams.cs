using System;
using System.IO;
using System.Threading;
using GeneralZip.Internal;

namespace GeneralZip.Formats.Codecs;

/// <summary>
/// 原生解码流（解压方向）：构造时经 Rust 核心"拉式"整段解码到临时文件，
/// 随后按普通流读取。相比旧双临时文件方案少一次密文拷贝；Dispose 时清理临时文件。
/// </summary>
internal sealed class NativeTempDecodeStream : Stream
{
    private readonly string _tempPath;
    private readonly PrivateTempDirectory _tempDirectory;
    private FileStream? _result;
    private bool _disposed;

    public NativeTempDecodeStream(Stream source, string codec, CancellationToken cancellationToken = default)
    {
        _tempDirectory = new PrivateTempDirectory("gzp-decode");
        _tempPath = _tempDirectory.FilePath("decoded.out");
        try
        {
            using (var output = File.Create(_tempPath, 65536))
            {
                NativeCodecRouter.DecompressStream(source, output, codec, cancellationToken);
            }

            var buffer = new byte[81920];
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            _result = new FileStream(_tempPath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536);
        }
        catch
        {
            _tempDirectory.Dispose();
            throw;
        }
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _result!.Length;
    public override long Position { get => _result!.Position; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => _result!.Read(buffer, offset, count);

    public override void Flush() { }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            _result?.Dispose();
            _result = null;
            _tempDirectory.Dispose();
        }

        base.Dispose(disposing);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// 原生编码流（压缩方向，供 TAR.BZ2 等流包装使用）：明文先写入临时工作文件，
/// Dispose 时经 Rust 核心整段压缩并投递到目标流。ZIP 条目写入走 NativeCodecRouter
/// 的直通流式路径，不经此类。
/// </summary>
internal sealed class NativeTempEncodeStream : Stream
{
    private readonly Stream _destination;
    private readonly string _codec;
    private readonly string _workPath;
    private FileStream? _work;
    private bool _finished;

    public NativeTempEncodeStream(Stream destination, string codec)
    {
        _destination = destination;
        _codec = codec;
        _workPath = Path.Combine(Path.GetTempPath(), $"gzp-encode-{Guid.NewGuid():N}.work");
        _work = new FileStream(_workPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count) => _work!.Write(buffer, offset, count);

    public override void Flush() => _work?.Flush();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_finished)
        {
            _finished = true;
            try
            {
                _work?.Dispose();
                _work = null;
                using var input = File.OpenRead(_workPath);
                NativeCodecRouter.CompressStream(input, _destination, _codec, level: 6, CancellationToken.None);
                _destination.Flush();
            }
            finally
            {
                try { File.Delete(_workPath); } catch { /* 清理失败忽略 */ }
            }
        }

        base.Dispose(disposing);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
