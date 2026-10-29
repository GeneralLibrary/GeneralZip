//! 单文件编解码格式（bzip2 / lz4 / zstd）经 C ABI 的整文件编解码。
//! 全部为纯 Rust 实现（libbz2-rs / lz4_flex / rust-zstd），无 C 工具链依赖。

use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::raw::{c_char, c_int};

use crate::caps::{set_error, str_from_c_ptr};
use crate::status;

/// 通用入口：按 codec 标识压缩文件（"bzip2" | "lz4" | "zstd"）。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_codec_compress(
    codec: *const c_char,
    src: *const c_char,
    dst: *const c_char,
) -> c_int {
    let result = std::panic::catch_unwind(|| compress_impl(codec, src, dst));
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("codec compress: 内部 panic");
            status::ERR_PANIC
        }
    }
}

/// 通用入口：按 codec 标识解压文件。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_codec_decompress(
    codec: *const c_char,
    src: *const c_char,
    dst: *const c_char,
) -> c_int {
    let result = std::panic::catch_unwind(|| decompress_impl(codec, src, dst));
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("codec decompress: 内部 panic");
            status::ERR_PANIC
        }
    }
}

fn compress_impl(codec: *const c_char, src: *const c_char, dst: *const c_char) -> c_int {
    let name = match str_from_c_ptr(codec) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let src = match str_from_c_ptr(src) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let dst = match str_from_c_ptr(dst) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let input = match open_source(&src) {
        Ok(f) => f,
        Err(code) => return code,
    };
    let output = match create_dest(&dst) {
        Ok(f) => f,
        Err(code) => return code,
    };

    let mut input = input;
    let mut output = BufWriter::new(output);

    let result = match name.as_str() {
        "bzip2" => {
            let mut encoder = bzip2::write::BzEncoder::new(
                output,
                bzip2::Compression::default(),
            );
            std::io::copy(&mut input, &mut encoder)
                .and_then(|_| encoder.finish().map(|_| ()))
        }
        "lz4" => {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(output);
            std::io::copy(&mut input, &mut encoder)
                .and_then(|_| {
                    encoder
                        .finish()
                        .map(|_| ())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                })
        }
        "zstd" => {
            // rust-zstd 0.4：压缩为一次性 API（内存缓冲）；解压为流式 Reader
            let mut data = Vec::new();
            if let Err(e) = input.read_to_end(&mut data) {
                set_error(format!("codec compress(zstd): 读取失败: {e}"));
                return status::ERR_IO;
            }
            let compressed = rust_zstd::compress(&data, 6);
            output.write_all(&compressed)
        }
        "xz" => crate::xz::xz_encode(&mut input, &mut output),
        other => {
            set_error(format!("codec compress: 不支持的编解码标识 {other}"));
            return status::ERR_ARG;
        }
    };

    match result {
        Ok(()) => status::OK,
        Err(e) => {
            set_error(format!("codec compress({name}): {e}"));
            status::ERR_IO
        }
    }
}

fn decompress_impl(codec: *const c_char, src: *const c_char, dst: *const c_char) -> c_int {
    let name = match str_from_c_ptr(codec) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let src = match str_from_c_ptr(src) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let dst = match str_from_c_ptr(dst) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let input = match open_source(&src) {
        Ok(f) => f,
        Err(code) => return code,
    };
    let output = match create_dest(&dst) {
        Ok(f) => f,
        Err(code) => return code,
    };

    let mut input = input;
    let mut output = BufWriter::new(output);

    let result = match name.as_str() {
        "bzip2" => {
            let mut decoder = bzip2::read::BzDecoder::new(input);
            std::io::copy(&mut decoder, &mut output)
        }
        "lz4" => {
            let mut decoder = lz4_flex::frame::FrameDecoder::new(input);
            std::io::copy(&mut decoder, &mut output)
        }
        "zstd" => {
            let mut decoder = rust_zstd::DecompressReader::new(input);
            std::io::copy(&mut decoder, &mut output)
        }
        "xz" => crate::xz::xz_decode(&mut input, &mut output).map(|_| 0u64),
        other => {
            set_error(format!("codec decompress: 不支持的编解码标识 {other}"));
            return status::ERR_ARG;
        }
    };

    match result {
        Ok(_) => {
            let _ = output.flush();
            status::OK
        }
        Err(e) => {
            set_error(format!("codec decompress({name}): {e}"));
            status::ERR_IO
        }
    }
}

fn open_source(path: &str) -> Result<BufReader<fs::File>, c_int> {
    fs::File::open(path)
        .map(BufReader::new)
        .map_err(|e| {
            set_error(format!("codec: 打开 {path} 失败: {e}"));
            status::ERR_IO
        })
}

fn create_dest(path: &str) -> Result<fs::File, c_int> {
    fs::File::create(path).map_err(|e| {
        set_error(format!("codec: 创建 {path} 失败: {e}"));
        status::ERR_IO
    })
}
