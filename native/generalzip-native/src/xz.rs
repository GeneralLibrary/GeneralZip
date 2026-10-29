//! xz 编解码：解压用 lzma-rs；压缩用 lzma_rust2（真 LZMA2）+ 手写最小 XZ 容器（check=None）。
//! （lzma-rs 0.3 的编码路径仅产出未压缩块，故弃用其压缩。）

use std::fs;
use std::io::{self, BufReader, Write};
use std::os::raw::{c_char, c_int};

use lzma_rust2::{CountingWriter, LZMA2Options, LZMA2Writer};

use crate::caps::{map_error, set_error, str_from_c_ptr};
use crate::status;

/// 压缩文件 → xz。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_xz_compress(src: *const c_char, dst: *const c_char) -> c_int {
    let result = std::panic::catch_unwind(|| compress_impl(src, dst));
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("xz compress: internal panic");
            status::ERR_PANIC
        }
    }
}

/// xz → 解压文件。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_xz_decompress(src: *const c_char, dst: *const c_char) -> c_int {
    let result = std::panic::catch_unwind(|| decompress_impl(src, dst));
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("xz decompress: internal panic");
            status::ERR_PANIC
        }
    }
}

unsafe fn compress_impl(src: *const c_char, dst: *const c_char) -> c_int {
    let src = match str_from_c_ptr(src) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let dst = match str_from_c_ptr(dst) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let input = match fs::File::open(&src) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            set_error(format!("xz: failed to open {src}: {e}"));
            return status::ERR_IO;
        }
    };
    let mut output = match fs::File::create(&dst) {
        Ok(f) => f,
        Err(e) => {
            set_error(format!("xz: failed to create {dst}: {e}"));
            return status::ERR_IO;
        }
    };

    let mut input = input;
    if let Err(e) = xz_encode(&mut input, &mut output) {
        return map_error(&e);
    }

    status::OK
}

unsafe fn decompress_impl(src: *const c_char, dst: *const c_char) -> c_int {
    let src = match str_from_c_ptr(src) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let dst = match str_from_c_ptr(dst) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let input = match fs::File::open(&src) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            set_error(format!("xz: failed to open {src}: {e}"));
            return status::ERR_IO;
        }
    };
    let mut output = match fs::File::create(&dst) {
        Ok(f) => f,
        Err(e) => {
            set_error(format!("xz: failed to create {dst}: {e}"));
            return status::ERR_IO;
        }
    };

    let mut input = input;
    if let Err(e) = xz_decode(&mut input, &mut output) {
        return map_error(&e);
    }

    status::OK
}

/// XZ 解码（lzma-rs）。
pub(crate) fn xz_decode<R: std::io::BufRead, W: io::Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    lzma_rs::xz_decompress(input, output).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

// ---------- 最小 XZ 容器编码（check = None） ----------

const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
const LZMA2_FILTER_ID: u8 = 0x21;
const LZMA2_DICT_PROPS: u8 = 22; // 8 MiB 字典

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, item) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        *item = c;
    }

    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// 产出合法 XZ 流：Stream Header + 单 Block（LZMA2，check=None）+ Index + Stream Footer。
pub(crate) fn xz_encode<R: std::io::BufRead, W: io::Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    // Stream Header：magic + flags(0,0 = check None) + CRC32(flags)
    output.write_all(&XZ_MAGIC)?;
    let stream_flags = [0x00u8, 0x00];
    output.write_all(&stream_flags)?;
    output.write_all(&crc32(&stream_flags).to_le_bytes())?;

    // Block：header + LZMA2 数据 + 对齐填充（check=None 无校验字段）
    let mut lzma2: Vec<u8> = Vec::new();
    let counting = CountingWriter::new(&mut lzma2);
    let _compressed_ref = counting.counting();
    let uncompressed_size;
    {
        let mut writer = LZMA2Writer::new(counting, &LZMA2Options::with_preset(6));
        uncompressed_size = io::copy(input, &mut writer)?;
        writer.finish()?;
    }
    let compressed_size = lzma2.len();

    let mut header: Vec<u8> = vec![0, 0x00, LZMA2_FILTER_ID, 0x01, LZMA2_DICT_PROPS];
    while header.len() % 4 != 0 {
        header.push(0);
    }
    header[0] = (header.len() / 4) as u8;

    // unpadded size = block header（含其 CRC32 的 4 字节）+ 压缩数据（不含块对齐填充与 check）
    let unpadded_size = header.len() + 4 + compressed_size;
    let mut padding = Vec::new();
    while (header.len() + 4 + compressed_size + padding.len() as usize) % 4 != 0 {
        padding.push(0);
    }

    output.write_all(&header)?;
    output.write_all(&crc32(&header).to_le_bytes())?;
    output.write_all(&lzma2)?;
    output.write_all(&padding)?;

    // Index：indicator + 记录数 + (unpadded, unpacked) + 对齐 + CRC32
    let mut index: Vec<u8> = vec![0x00];
    write_varint(&mut index, 1);
    write_varint(&mut index, unpadded_size as u64);
    write_varint(&mut index, uncompressed_size as u64);
    while index.len() % 4 != 0 {
        index.push(0);
    }
    output.write_all(&index)?;
    output.write_all(&crc32(&index).to_le_bytes())?;

    // Stream Footer：CRC32(backward+flags) + backward_size + flags + "YZ"
    // backward_size = 实际索引区（含 CRC32 共 12B）÷4 − 1；index.len() 不含 CRC32
    let backward_size = (index.len() as u32) / 4;
    let mut footer: Vec<u8> = Vec::new();
    footer.extend_from_slice(&(backward_size).to_le_bytes());
    footer.extend_from_slice(&stream_flags);
    let footer_crc = crc32(&footer);
    output.write_all(&footer_crc.to_le_bytes())?;
    output.write_all(&footer)?;
    output.write_all(b"YZ")?;

    output.flush()?;
    Ok(())
}
