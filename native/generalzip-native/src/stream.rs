//! 流式编解码：经 C# 回调推拉的零临时文件转码。
//!
//! 压缩（crun）：Rust 经 `read_cb` 拉取明文（C# 侧读源流），编码器输出经 `write_cb`
//! 直接推回 C#（写入加密管道/目标流）。单调用跑完，天然支持取消与进度（回调内检查）。
//! 解压（drun）：对称地，Rust 经 `read_cb` 拉密文、经 `write_cb` 推明文。
//!
//! 编解码器（纯 Rust）：bzip2 / zstd / lz4 / xz / lzma-zip（ZIP method 14 框架）/ brotli。
//! 边界纪律：回调返回负数视为失败并中止；任何 panic 经 catch_unwind 兜底。

use std::io::{self, BufReader, Read, Write};
use std::os::raw::{c_char, c_int, c_void};

use crate::caps::{set_error, str_from_c_ptr};
use crate::status;

/// 读取回调：填 buf（≤cap），返回读取字节数；0 = EOF；负数 = 失败。
pub type ReadCb = unsafe extern "system" fn(buf: *mut u8, cap: u32, user: *mut c_void) -> i32;
/// 写入回调：消费 buf（len 字节），0 = 成功；负数 = 失败。
pub type WriteCb = unsafe extern "system" fn(buf: *const u8, len: u32, user: *mut c_void) -> i32;

/// 回调适配的输入流（拉式）。
struct CbReader {
    read_cb: ReadCb,
    user: *mut c_void,
    eof: bool,
}

impl Read for CbReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof || buf.is_empty() {
            return Ok(0);
        }

        let ret = unsafe { (self.read_cb)(buf.as_mut_ptr(), buf.len() as u32, self.user) };
        if ret > 0 {
            Ok(ret as usize)
        } else if ret == 0 {
            self.eof = true;
            Ok(0)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("read callback failed ({ret})"),
            ))
        }
    }
}

/// 回调适配的输出流（推式）。
struct CbWriter {
    write_cb: WriteCb,
    user: *mut c_void,
}

impl Write for CbWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let ret = unsafe { (self.write_cb)(buf.as_ptr(), buf.len() as u32, self.user) };
        if ret == 0 {
            Ok(buf.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("write callback failed ({ret})"),
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 跳过输出流中 [from, to) 区间的字节（用于剥离 .lzma alone 头部的 size 字段）。
struct SkippingWriter<W: Write> {
    inner: W,
    skip_from: u64,
    skip_to: u64,
    pos: u64,
}

impl<W: Write> Write for SkippingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0usize;
        while written < buf.len() {
            let abs = self.pos;
            if abs >= self.skip_from && abs < self.skip_to {
                // 处于跳过区：静默丢弃到区间末或缓冲尾
                let advance = (self.skip_to - abs).min((buf.len() - written) as u64) as usize;
                self.pos += advance as u64;
                written += advance;
                continue;
            }

            // 连续可写段：写到跳过区起点或缓冲尾
            let seg_end = if abs < self.skip_from && (self.skip_from - abs) < (buf.len() - written) as u64 {
                written + (self.skip_from - abs) as usize
            } else {
                buf.len()
            };
            let n = self.inner.write(&buf[written..seg_end])?;
            if n == 0 {
                break;
            }

            self.pos += n as u64;
            written += n;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// 单字节回推流：多帧拼接解码时保留"偷看"到的下一帧首字节。
struct PushbackReader<'a> {
    inner: &'a mut dyn Read,
    pushback: Option<u8>,
}

impl Read for PushbackReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if let Some(b) = self.pushback.take() {
            buf[0] = b;
            return Ok(1);
        }

        self.inner.read(buf)
    }
}

// ---------- 编解码器分发 ----------

fn compress_with<R: Read, W: Write>(codec: &str, level: u32, input: &mut R, output: &mut W) -> io::Result<()> {
    match codec {
        "bzip2" => {
            let mut encoder = bzip2::write::BzEncoder::new(output, bzip2::Compression::default());
            io::copy(input, &mut encoder)?;
            encoder.finish().map(|_| ())
        }
        "zstd" => {
            let opts = rust_zstd::compress::CompressOptions {
                level: clamp_zstd_level(level),
                ..Default::default()
            };
            let mut encoder = rust_zstd::compress::Encoder::new(output, opts);
            io::copy(input, &mut encoder)?;
            encoder.finish().map(|_| ())
        }
        "lz4" => {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(output);
            io::copy(input, &mut encoder)?;
            encoder.finish().map(|_| ()).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
        }
        "xz" => {
            // lzma-rs 0.3 的压缩为纯字面量（无匹配），复用 xz.rs 的 lzma_rust2 编码路径
            let mut buffered = BufReader::new(input);
            crate::xz::xz_encode(&mut buffered, output)
        }
        "lzma-zip" => {
            // ZIP method 14 帧：ver(2) propsize(2) props(N) + LZMA1 流（带 EOPM）
            // 输出 = 4B 头 + alone 头（props+dict+size）+ 流；剥离 alone 头中的 8B size 字段
            output.write_all(&[0x09, 0x16, 0x05, 0x00])?;
            let mut skip = SkippingWriter {
                inner: output,
                skip_from: 9,  // 4(zip 头)+1(props)+4(dict) 之后
                skip_to: 17,   // 8B 未压缩大小字段
                pos: 0,
            };
            let options = lzma_rs::compress::Options {
                unpacked_size: lzma_rs::compress::UnpackedSize::WriteToHeader(None), // FFFF..FF + EOPM
            };
            let mut buffered = BufReader::new(input);
            lzma_rs::lzma_compress_with_options(&mut buffered, &mut skip, &options)
        }
        "brotli" => {
            // CompressorWriter 在 Drop 时刷出终结块
            let mut encoder = brotli::CompressorWriter::new(output, 65536, clamp_brotli_level(level), 22);
            io::copy(input, &mut encoder)?;
            encoder.flush()?;
            drop(encoder);
            Ok(())
        }
        other => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported codec id {other}"))),
    }
}

fn decompress_with<R: Read, W: Write>(codec: &str, input: &mut R, output: &mut W) -> io::Result<()> {
    match codec {
        "bzip2" => {
            let mut decoder = bzip2::read::BzDecoder::new(input);
            io::copy(&mut decoder, output).map(|_| ())
        }
        "zstd" => {
            // 支持拼接多帧：单帧 EOF 后若输入未尽则续开新解码器
            let mut source = PushbackReader { inner: input, pushback: None };
            loop {
                let mut decoder = rust_zstd::DecompressReader::new(&mut source);
                let _ = io::copy(&mut decoder, output)?;
                // 解码器 EOF：偷看一字节判断是否还有下一帧
                let mut probe = [0u8; 1];
                let n = source.read(&mut probe)?;
                if n == 0 {
                    return Ok(());
                }

                source.pushback = Some(probe[0]);
            }
        }
        "lz4" => {
            let mut decoder = lz4_flex::frame::FrameDecoder::new(input);
            io::copy(&mut decoder, output).map(|_| ())
        }
        "xz" => {
            let mut buffered = BufReader::new(input);
            crate::xz::xz_decode(&mut buffered, output)
        }
        "lzma-zip" => {
            // 重建 alone 头：props(N) + size=FFFF..FF，然后接剩余流（EOPM 结束）
            let mut version = [0u8; 2];
            input.read_exact(&mut version)?;
            let mut propsize_buf = [0u8; 2];
            input.read_exact(&mut propsize_buf)?;
            let propsize = u16::from_le_bytes(propsize_buf) as usize;
            let mut props = vec![0u8; propsize];
            input.read_exact(&mut props)?;

            let mut prefix = Vec::with_capacity(propsize + 8);
            prefix.extend_from_slice(&props);
            prefix.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFF_u64.to_le_bytes());

            let mut chained = prefix.chain(BufReader::new(input));
            lzma_rs::lzma_decompress(&mut chained, output).map_err(lzma_err)
        }
        "brotli" => {
            let mut decoder = brotli::Decompressor::new(input, 65536);
            io::copy(&mut decoder, output).map(|_| ())
        }
        other => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported codec id {other}"))),
    }
}

/// lzma_rs 自有错误类型 → io::Error。
fn lzma_err(e: lzma_rs::error::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

fn clamp_zstd_level(level: u32) -> i32 {
    if level == 0 {
        3
    } else {
        (level as i32).clamp(1, 22)
    }
}

fn clamp_brotli_level(level: u32) -> u32 {
    if level == 0 {
        9
    } else {
        level.clamp(1, 11)
    }
}

// ---------- FFI ----------

/// 流式压缩：拉明文 → 推密文。返回 status；错误详情经 gzp_last_error。
///
/// # Safety
/// 指针与回调必须有效；回调不得重入本核心。
#[no_mangle]
pub unsafe extern "system" fn gzp_codec_crun(
    codec: *const c_char,
    level: u32,
    read_cb: ReadCb,
    write_cb: WriteCb,
    user: *mut c_void,
) -> c_int {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crun_impl(codec, level, read_cb, write_cb, user)
    }));
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("codec stream compress: internal panic");
            status::ERR_PANIC
        }
    }
}

/// 流式解压：拉密文 → 推明文。
///
/// # Safety
/// 指针与回调必须有效；回调不得重入本核心。
#[no_mangle]
pub unsafe extern "system" fn gzp_codec_drun(
    codec: *const c_char,
    read_cb: ReadCb,
    write_cb: WriteCb,
    user: *mut c_void,
) -> c_int {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drun_impl(codec, read_cb, write_cb, user)
    }));
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("codec stream decompress: internal panic");
            status::ERR_PANIC
        }
    }
}

fn crun_impl(codec: *const c_char, level: u32, read_cb: ReadCb, write_cb: WriteCb, user: *mut c_void) -> c_int {
    let name = match str_from_c_ptr(codec) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let mut input = CbReader { read_cb, user, eof: false };
    let mut output = CbWriter { write_cb, user };

    match compress_with(&name, level, &mut input, &mut output) {
        Ok(()) => status::OK,
        Err(e) => {
            set_error(format!("codec stream compress({name}): {e}"));
            status::ERR_IO
        }
    }
}

fn drun_impl(codec: *const c_char, read_cb: ReadCb, write_cb: WriteCb, user: *mut c_void) -> c_int {
    let name = match str_from_c_ptr(codec) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let mut input = CbReader { read_cb, user, eof: false };
    let mut output = CbWriter { write_cb, user };

    match decompress_with(&name, &mut input, &mut output) {
        Ok(()) => status::OK,
        Err(e) => {
            set_error(format!("codec stream decompress({name}): {e}"));
            status::ERR_IO
        }
    }
}
