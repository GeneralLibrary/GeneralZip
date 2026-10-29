using System;
using System.IO;

namespace GeneralZip.Formats.Codecs;

/// <summary>原生编解码方向。</summary>
internal enum NativeCodecMode
{
    Compress,
    Decompress,
}

/// <summary>
/// 原生编解码的流包装（双临时文件整段编解码）：
/// - Compress：明文写入工作文件，Dispose 时调用原生核心压缩，产物投递到目标流；
/// - Decompress：构造时把来源流存为密文工作文件，原生解码到产物文件后按普通流读取。
/// 工作文件与产物文件分离，避免同路径句柄互斥。
/// </summary>
internal sealed class NativeTempCodecStream : Stream
{
    private readonly Stream? _destination;
    private readonly Stream? _source;
    private readonly string _codec;
    private readonly bool _compress;
    private readonly string _workPath;   // 压缩：明文；解压：密文
    private readonly string _resultPath; // 编解码产物
    private FileStream? _work;
    private FileStream? _result;
    private bool _finished;

    private NativeTempCodecStream(string codec, bool compress)
    {
        _codec = codec;
        _compress = compress;
        var id = Guid.NewGuid().ToString("N");
        _workPath = Path.Combine(Path.GetTempPath(), $"gzp-codec-{id}.work");
        _resultPath = Path.Combine(Path.GetTempPath(), $"gzp-codec-{id}.out");
    }

    /// <summary>按模式包装流：Compress → stream 为目标流；Decompress → stream 为来源流（立即整段解码）。</summary>
    public NativeTempCodecStream(Stream stream, string codec, NativeCodecMode mode)
        : this(codec, compress: mode == NativeCodecMode.Compress)
    {
        if (mode == NativeCodecMode.Compress)
        {
            _destination = stream ?? throw new ArgumentNullException(nameof(stream));
            _work = new FileStream(_workPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536);
        }
        else
        {
            _source = stream ?? throw new ArgumentNullException(nameof(stream));

            // 来源流 → 密文工作文件（写完关闭，避免共享锁冲突）→ 原生解码 → 产物文件
            using (var work = File.Create(_workPath, 65536))
            {
                _source.CopyTo(work, 65536);
            }

            NativeCodecRouter.Decompress(_codec, _workPath, _resultPath);
            _result = new FileStream(_resultPath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536);
        }
    }

    public override bool CanRead => !_compress;
    public override bool CanSeek => false;
    public override bool CanWrite => _compress;
    public override long Length => _compress ? throw new NotSupportedException() : _result!.Length;
    public override long Position { get => _compress ? throw new NotSupportedException() : _result!.Position; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_compress) throw new NotSupportedException();
        return _result!.Read(buffer, offset, count);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (!_compress) throw new NotSupportedException();
        _work!.Write(buffer, offset, count);
    }

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
                _result?.Dispose();
                _result = null;

                if (_compress)
                {
                    NativeCodecRouter.Compress(_codec, _workPath, _resultPath);
                    using var compressed = File.OpenRead(_resultPath);
                    compressed.CopyTo(_destination!, 65536);
                    _destination!.Flush();
                }
            }
            finally
            {
                TryDelete(_workPath);
                TryDelete(_resultPath);
            }
        }

        base.Dispose(disposing);
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* 清理失败忽略 */ }
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
