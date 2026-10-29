//! RAR 解密读取（feature `rar`）：封装官方 unrar 源码（unrar crate）。
//! RAR 压缩算法专有，仅支持读取。进度回调参数保留 ABI 位置，v1 未实现细粒度上报。

use std::os::raw::{c_char, c_int, c_void};
use std::path::PathBuf;

use crate::caps::{password_from_ptr, set_error, str_from_c_ptr};
use crate::status;
use crate::{json_escape, ProgressCb};

/// 列出条目 → JSON 数组（两段式：out 为 NULL 时回填所需长度）。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_rar_list_json(
    path: *const c_char,
    password: *const u8,
    password_len: u32,
    out: *mut u8,
    cap: u32,
    out_len: *mut u32,
) -> c_int {
    if out_len.is_null() {
        return status::ERR_ARG;
    }
    *out_len = 0;

    let result = std::panic::catch_unwind(|| {
        let path = match str_from_c_ptr(path) {
            Ok(p) => p.to_string(),
            Err(e) => return Err(e),
        };
        let password = password_from_ptr(password, password_len);
        list_impl(&path, password.as_deref())
    });

    match result {
        Ok(Ok(json)) => {
            let bytes = json.as_bytes();
            *out_len = bytes.len() as u32;
            if out.is_null() {
                return status::ERR_BUFFER;
            }
            if bytes.len() as u32 > cap {
                return status::ERR_BUFFER;
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            status::OK
        }
        Ok(Err(code)) => code,
        Err(_) => {
            set_error("rar list: internal panic");
            status::ERR_PANIC
        }
    }
}

/// 解压：index = -1 全部，否则单条目。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_rar_extract(
    path: *const c_char,
    password: *const u8,
    password_len: u32,
    index: i64,
    dest_dir: *const c_char,
    progress: ProgressCb,
    user: *mut c_void,
) -> c_int {
    let _ = (progress, user); // v1：RAR 进度暂不实现细粒度上报

    let result = std::panic::catch_unwind(|| {
        extract_impl(path, password_from_ptr(password, password_len), index, dest_dir)
    });
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("rar extract: internal panic");
            status::ERR_PANIC
        }
    }
}

fn list_impl(path: &str, password: Option<&str>) -> Result<String, c_int> {
    let open = match unrar::Archive::new(path).open_for_listing() {
        Ok(o) => o,
        Err(e) => return Err(map_error(&e)),
    };
    let open = apply_password(open, password)?;

    let mut json = String::from("[");
    let mut first = true;
    for entry in open {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => return Err(map_process_error(&e)),
        };

        if !first {
            json.push(',');
        }
        first = false;

        json.push_str("{\"name\":\"");
        json_escape(&entry.filename.to_string(), &mut json);
        json.push_str("\",\"size\":");
        json.push_str(&entry.uncompressed_size.to_string());
        json.push_str(",\"isDir\":");
        json.push_str(if entry.is_directory() { "true" } else { "false" });
        json.push_str(",\"mtime\":0,\"hasMtime\":false}");
    }
    json.push(']');
    Ok(json)
}

fn extract_impl(
    path: *const c_char,
    password: Option<String>,
    index: i64,
    dest_dir: *const c_char,
) -> c_int {
    let path = match str_from_c_ptr(path) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let dest_dir = match str_from_c_ptr(dest_dir) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let dest = PathBuf::from(&dest_dir);

    if index < 0 {
        // 全部条目
        let extraction = match unrar::Archive::new(&path).open_for_extraction() {
            Ok(x) => x,
            Err(e) => return map_error(&e),
        };
        let extraction = match apply_password(extraction, password.as_deref()) {
            Ok(x) => x,
            Err(code) => return code,
        };

        return match extraction.extract_to(&dest) {
            Ok(_result) => status::OK,
            Err(e) => map_process_error(&e),
        };
    }

    // 单条目：先列表取条目名
    let list = match unrar::Archive::new(&path).open_for_listing() {
        Ok(l) => l,
        Err(e) => return map_error(&e),
    };
    let list = match apply_password(list, password.as_deref()) {
        Ok(l) => l,
        Err(code) => return code,
    };

    let mut names: Vec<String> = Vec::new();
    for entry in list {
        match entry {
            Ok(e) => names.push(e.filename.to_string()),
            Err(e) => return map_process_error(&e),
        }
    }

    if (index as usize) >= names.len() {
        set_error(format!("rar: entry index out of range {index} (of {})", names.len()));
        return status::ERR_ARG;
    }

    let target_rel = &names[index as usize];
    let extraction = match unrar::Archive::new(&path).open_for_extraction() {
        Ok(x) => x,
        Err(e) => return map_error(&e),
    };
    let extraction = match apply_password(extraction, password.as_deref()) {
        Ok(x) => x,
        Err(code) => return code,
    };

    if let Some(parent) = PathBuf::from(sanitize_rel(target_rel)).parent() {
        let full = dest.join(parent);
        let _ = std::fs::create_dir_all(full);
    }

    let dest_file = dest.join(sanitize_rel(target_rel));
    match extraction.extract_file_to(target_rel, &dest_file) {
        Ok(_) => status::OK,
        Err(e) => map_process_error(&e),
    }
}

fn apply_password(open: unrar::OpenArchive, password: Option<&str>) -> Result<unrar::OpenArchive, c_int> {
    match password {
        Some(pw) => open.set_password(pw).map_err(|_| {
            set_error("rar: failed to apply password");
            status::ERR_PASSWORD
        }),
        None => Ok(open),
    }
}

fn map_error(e: &unrar::error::Error) -> c_int {
    let text = e.to_string();
    set_error(format!("rar: {text}"));
    status::ERR_FORMAT
}

fn map_process_error(e: &unrar::error::ProcessError) -> c_int {
    let text = e.to_string();
    let lower = text.to_lowercase();
    let code = if lower.contains("password") {
        status::ERR_PASSWORD
    } else if lower.contains("crc") {
        status::ERR_FORMAT
    } else {
        status::ERR_IO
    };
    set_error(format!("rar: {text}"));
    code
}

fn sanitize_rel(name: &str) -> PathBuf {
    let normalized = name.replace('\\', "/");
    let mut parts: Vec<String> = Vec::new();
    for seg in normalized.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg.to_string());
    }
    parts.into_iter().collect()
}
