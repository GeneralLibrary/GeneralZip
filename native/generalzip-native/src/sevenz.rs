//! 7z 读写（含 AES-256 加密），基于 sevenz-rust2。

use std::fs;
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};

use sevenz_rust2::{
    AesEncoderOptions, Password, SevenZArchiveEntry, SevenZReader, SevenZWriter,
};

use crate::caps::{password_from_ptr, set_error, str_from_c_ptr};
use crate::status;
use crate::{json_escape, CountingReader, ProgressCb, ProgressGate};

/// 统一把 sevenz_rust2::Error 映射为状态码（口令错误独立标识，供上层重询问）。
fn map_sz_error(err: &sevenz_rust2::Error) -> c_int {
    use sevenz_rust2::Error::*;
    let text = err.to_string();
    let code = match err {
        PasswordRequired | MaybeBadPassword(_) => status::ERR_PASSWORD,
        FileNotFound => status::ERR_NOT_FOUND,
        BadSignature(_) | UnsupportedVersion { .. } | UnsupportedCompressionMethod(_)
        | Unsupported(_) | ExternalUnsupported => status::ERR_FORMAT,
        ChecksumVerificationFailed | NextHeaderCrcMismatch => status::ERR_FORMAT,
        Io(_, _) | FileOpen(_, _) => status::ERR_IO,
        _ => status::ERR_FORMAT,
    };
    set_error(format!("7z: {text}"));
    code
}

fn make_password(pw: Option<String>) -> Password {
    match pw {
        Some(s) => Password::from(s.as_str()), // 7z 规范：UTF-16LE
        None => Password::empty(),
    }
}

/// 列出条目 → JSON 数组文本（两段式：缓冲不足返回 ERR_BUFFER 并回填所需长度）。
///
/// # Safety
/// path/out/out_len 必须为调用方持有的有效指针。
#[no_mangle]
pub unsafe extern "system" fn gzp_7z_list_json(
    path: *const c_char,
    password: *const u8,
    password_len: u32,
    out: *mut u8,
    cap: u32,
    out_len: *mut u32,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        list_json_impl(
            path,
            password_from_ptr(password, password_len),
            out,
            cap,
            out_len,
        )
    });
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("7z list: internal panic");
            if !out_len.is_null() {
                *out_len = 0;
            }
            status::ERR_PANIC
        }
    }
}

unsafe fn list_json_impl(
    path: *const c_char,
    password: Option<String>,
    out: *mut u8,
    cap: u32,
    out_len: *mut u32,
) -> c_int {
    if out_len.is_null() {
        return status::ERR_ARG;
    }
    *out_len = 0;

    let path = match str_from_c_ptr(path) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let json = match list_inner(&path, make_password(password)) {
        Ok(j) => j,
        Err(e) => return e,
    };

    let bytes = json.as_bytes();
    *out_len = bytes.len() as u32;
    if out.is_null() {
        return status::ERR_BUFFER; // 仅查询所需长度
    }
    if (bytes.len() as u32) > cap {
        return status::ERR_BUFFER;
    }

    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    status::OK
}

fn list_inner(path: &str, password: Password) -> Result<String, c_int> {
    let mut reader = SevenZReader::open(path, password).map_err(|e| map_sz_error(&e))?;

    let mut json = String::from("[");
    let mut first = true;
    reader
        .for_each_entries(|entry, _reader| {
            if !first {
                json.push(',');
            }
            first = false;

            json.push_str("{\"name\":\"");
            json_escape(&entry.name, &mut json);
            json.push_str("\",\"size\":");
            json.push_str(&entry.size.to_string());
            json.push_str(",\"isDir\":");
            json.push_str(if entry.is_directory { "true" } else { "false" });
            json.push_str(",\"mtime\":");
            json.push_str(&u64::from(entry.last_modified_date).to_string());
            json.push_str(",\"hasMtime\":");
            json.push_str(if entry.has_last_modified_date { "true" } else { "false" });
            json.push('}');

            Ok(true) // 继续
        })
        .map_err(|e| map_sz_error(&e))?;

    json.push(']');
    Ok(json)
}

/// 解压：index = -1 全部（dest_dir 为目录），否则单条目解到 dest_dir 指定文件。
///
/// # Safety
/// 各指针必须为调用方持有的有效指针；cb/user 由 C# 侧保活。
#[no_mangle]
pub unsafe extern "system" fn gzp_7z_extract(
    path: *const c_char,
    password: *const u8,
    password_len: u32,
    index: i64,
    dest_dir: *const c_char,
    progress: ProgressCb,
    user: *mut c_void,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        extract_impl(
            path,
            password_from_ptr(password, password_len),
            index,
            dest_dir,
            index < 0,
            progress,
            user,
        )
    });
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("7z extract: internal panic");
            status::ERR_PANIC
        }
    }
}

unsafe fn extract_impl(
    path: *const c_char,
    password: Option<String>,
    index: i64,
    dest_dir: *const c_char,
    as_dir: bool,
    progress: ProgressCb,
    user: *mut c_void,
) -> c_int {
    let path = match str_from_c_ptr(path) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let dest_dir = match str_from_c_ptr(dest_dir) {
        Ok(p) => PathBuf::from(p),
        Err(e) => return e,
    };

    let pw = make_password(password.clone());
    let mut reader = match SevenZReader::open(&path, pw) {
        Ok(r) => r,
        Err(e) => return map_sz_error(&e),
    };

    // 总量（用于进度）
    let mut total: u64 = 0;
    let mut names: Vec<String> = Vec::new();
    if let Err(e) = reader.for_each_entries(|entry, _r| {
        if !entry.is_directory {
            total = total.saturating_add(entry.size);
        }
        names.push(entry.name.clone());
        Ok(true)
    }) {
        return map_sz_error(&e);
    }

    // 需要解压的条目集合
    let want_all = index < 0;
    if !want_all && (index as usize) >= names.len() {
        set_error(format!("7z: entry index out of range {index} (of {})", names.len()));
        return status::ERR_ARG;
    }

    let want_index = index as usize;
    let mut gate = ProgressGate::new(progress, user, total);
    let mut pw = password;

    // 口令重试循环：遇到口令错误时以新口令重开（重开代价为重新解析头部，可接受）
    loop {
        let password_opt = pw.clone();
        let mut reader = match SevenZReader::open(&path, make_password(password_opt.clone())) {
            Ok(r) => r,
            Err(e) => return map_sz_error(&e),
        };

        let mut done_before = gate.done();
        let res: Result<(), c_int> = (|| {
            let mut index_seen: usize = 0;
            reader
                .for_each_entries(|entry, stream| {
                    let entry_index = index_seen;
                    index_seen += 1;

                    let should_extract = want_all || entry_index == want_index;
                    if !should_extract || entry.is_directory {
                        if should_extract && as_dir {
                            let dir = dest_dir.join(sanitize_rel(&entry.name));
                            let _ = fs::create_dir_all(dir);
                        }
                        return Ok(true);
                    }

                    let rel = sanitize_rel(&entry.name);
                    let target = if as_dir {
                        dest_dir.join(&rel)
                    } else {
                        dest_dir.to_path_buf()
                    };
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent).map_err(|e| {
                            set_error(format!("failed to create directory {:?}: {e}", parent));
                            sevenz_rust2::Error::io(e)
                        })?;
                    }

                    let mut counting = CountingReader::new(stream, &mut gate);
                    let mut file = fs::File::create(&target).map_err(|e| {
                        set_error(format!("failed to create file {:?}: {e}", target));
                        sevenz_rust2::Error::io(e)
                    })?;
                    std::io::copy(&mut counting, &mut file).map_err(|e| {
                        set_error(format!("failed to write entry {:?}: {e}", rel));
                        sevenz_rust2::Error::io(e)
                    })?;
                    let _ = done_before;
                    Ok(true)
                })
                .map_err(|e| map_sz_error(&e))?;
            Ok(())
        })();

        match res {
            Ok(()) => {
                let _ = pw;
                return status::OK;
            }
            Err(status::ERR_PASSWORD) => {
                // 由 C# 侧经 gzip? no——本核心不含口令回调；直接上报口令错误，
                // C# 包装层询问新口令后重试整次调用。
                return status::ERR_PASSWORD;
            }
            Err(e) => return e,
        }
    }
}

/// 压缩：sources 为 JSON 字符串数组（文件或目录，递归）；密码为空则不加密。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_7z_compress(
    sources_json: *const c_char,
    dest: *const c_char,
    password: *const u8,
    password_len: u32,
    progress: ProgressCb,
    user: *mut c_void,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        compress_impl(
            sources_json,
            dest,
            password_from_ptr(password, password_len),
            progress,
            user,
        )
    });
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("7z compress: internal panic");
            status::ERR_PANIC
        }
    }
}

unsafe fn compress_impl(
    sources_json: *const c_char,
    dest: *const c_char,
    password: Option<String>,
    progress: ProgressCb,
    user: *mut c_void,
) -> c_int {
    let sources_text = match str_from_c_ptr(sources_json) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };
    let dest = match str_from_c_ptr(dest) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let sources = match parse_json_string_array(&sources_text) {
        Some(v) => v,
        None => {
            set_error("sources is not a valid JSON string array");
            return status::ERR_ARG;
        }
    };

    // 展开源路径 → (绝对路径, 归档内相对名)
    let mut jobs: Vec<(PathBuf, String)> = Vec::new();
    let mut total: u64 = 0;
    for src in &sources {
        let p = PathBuf::from(src);
        let file_name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "root".to_string());

        if p.is_dir() {
            // 以父目录为根推导相对名，保留目录前缀（7-Zip 语义：压缩目录 → "data/a.txt"）
            let root = p.parent().map(|x| x.to_path_buf()).unwrap_or_else(|| p.clone());
            jobs.insert(0, (p.clone(), format!("{file_name}/")));
            collect_dir(&root, &p, &mut jobs, &mut total);
        } else if p.is_file() {
            match fs::metadata(&p) {
                Ok(m) => total = total.saturating_add(m.len()),
                Err(e) => {
                    set_error(format!("failed to read {src}: {e}"));
                    return status::ERR_NOT_FOUND;
                }
            }
            jobs.push((p, file_name));
        } else {
            set_error(format!("source path does not exist: {src}"));
            return status::ERR_NOT_FOUND;
        }
    }

    let mut gate = ProgressGate::new(progress, user, total);

    let mut writer = match SevenZWriter::create(&dest) {
        Ok(w) => w,
        Err(e) => return map_sz_error(&e),
    };

    if let Some(pw) = &password {
        writer.set_content_methods(vec![
            AesEncoderOptions::new(Password::from(pw.as_str())).into(),
            sevenz_rust2::SevenZMethod::LZMA2.into(),
        ]);
        // 头部加密沿用默认开启（与 7-Zip "加密文件名" 一致性由上层选项决定，v1 默认开）
    }

    for (path, entry_name) in &jobs {
        if entry_name.ends_with('/') {
            let mut entry = SevenZArchiveEntry::new_folder(entry_name);
            entry.has_last_modified_date = true;
            entry.last_modified_date = file_time_now();
            if let Err(e) = writer.push_archive_entry(entry, None::<&mut std::io::Empty>) {
                return map_sz_error(&e);
            }
            continue;
        }

        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                set_error(format!("failed to open file {path:?}: {e}"));
                return status::ERR_IO;
            }
        };
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        let mut entry = SevenZArchiveEntry::new_file(entry_name);
        entry.has_stream = true;
        entry.size = size;
        entry.has_last_modified_date = true;
        entry.last_modified_date = file_mtime(path);

        let mut counting = CountingReader::new(file, &mut gate);
        if let Err(e) = writer.push_archive_entry(entry, Some(&mut counting)) {
            return map_sz_error(&e);
        }
    }

    match writer.finish() {
        Ok(_) => status::OK,
        Err(e) => map_io_error(&e),
    }
}

/// 完整性测试（解压到内存丢弃）。
///
/// # Safety
/// 指针必须有效。
#[no_mangle]
pub unsafe extern "system" fn gzp_7z_test(
    path: *const c_char,
    password: *const u8,
    password_len: u32,
    progress: ProgressCb,
    user: *mut c_void,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        test_impl(path, password_from_ptr(password, password_len), progress, user)
    });
    match result {
        Ok(r) => r,
        Err(_) => {
            set_error("7z test: internal panic");
            status::ERR_PANIC
        }
    }
}

unsafe fn test_impl(
    path: *const c_char,
    password: Option<String>,
    progress: ProgressCb,
    user: *mut c_void,
) -> c_int {
    let path = match str_from_c_ptr(path) {
        Ok(p) => p.to_string(),
        Err(e) => return e,
    };

    let mut reader = match SevenZReader::open(&path, make_password(password)) {
        Ok(r) => r,
        Err(e) => return map_sz_error(&e),
    };

    let mut total: u64 = 0;
    if let Err(e) = reader.for_each_entries(|entry, _r| {
        if !entry.is_directory {
            total = total.saturating_add(entry.size);
        }
        Ok(true)
    }) {
        return map_sz_error(&e);
    }

    let mut gate = ProgressGate::new(progress, user, total);
    let mut sink = std::io::sink();
    if let Err(e) = reader.for_each_entries(|entry, stream| {
        if entry.is_directory {
            return Ok(true);
        }
        let mut counting = CountingReader::new(stream, &mut gate);
        std::io::copy(&mut counting, &mut sink).map_err(|e| {
            set_error(format!("7z test: {e}"));
            sevenz_rust2::Error::io(e)
        })?;
        Ok(true)
    }) {
        return map_sz_error(&e);
    }

    status::OK
}

// ---------- 工具 ----------

/// std::io::Error → 状态码（写入器错误类别）。
fn map_io_error(e: &std::io::Error) -> c_int {
    set_error(format!("7z: {e}"));
    status::ERR_IO
}

/// 归档内路径 → 目标相对路径（拒绝绝对路径/穿越，逐段清洗）。
fn sanitize_rel(name: &str) -> PathBuf {
    let normalized = name.replace('\\', "/");
    let mut parts = Vec::new();
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

fn collect_dir(root: &Path, dir: &Path, jobs: &mut Vec<(PathBuf, String)>, total: &mut u64) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    // 目录条目先于文件条目（保证解压端目录存在性）
    let mut subdirs = Vec::new();
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else {
            files.push(path);
        }
    }

    for sub in &subdirs {
        let rel = rel_from(root, sub);
        jobs.push((sub.clone(), rel));
        collect_dir(root, sub, jobs, total);
    }

    for file in &files {
        let rel = rel_from(root, file);
        if let Ok(m) = fs::metadata(file) {
            *total = total.saturating_add(m.len());
        }
        jobs.push((file.clone(), rel));
    }
}

fn rel_from(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let text = rel.to_string_lossy().replace('\\', "/");
    if path.is_dir() {
        format!("{text}/")
    } else {
        text
    }
}

fn file_mtime(path: &Path) -> sevenz_rust2::nt_time::FileTime {
    use sevenz_rust2::nt_time::FileTime;
    let secs = fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    FileTime::from_unix_time(secs, 0).unwrap_or(FileTime::UNIX_EPOCH)
}

fn file_time_now() -> sevenz_rust2::nt_time::FileTime {
    use sevenz_rust2::nt_time::FileTime;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    FileTime::from_unix_time(secs, 0).unwrap_or(FileTime::UNIX_EPOCH)
}

/// 极简 JSON 字符串数组解析（由本核心自身生成的格式，转义规则已知）。
pub(crate) fn parse_json_string_array(text: &str) -> Option<Vec<String>> {
    let trimmed = text.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c == ',' || c.is_whitespace() {
            chars.next();
            continue;
        }
        if c != '"' {
            return None;
        }
        chars.next();
        let mut s = String::new();
        loop {
            match chars.next() {
                Some('"') => break,
                Some('\\') => match chars.next() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('/') => s.push('/'),
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('u') => {
                        let mut hex = String::new();
                        for _ in 0..4 {
                            hex.push(chars.next()?);
                        }
                        let code = u32::from_str_radix(&hex, 16).ok()?;
                        s.push(char::from_u32(code)?);
                    }
                    _ => return None,
                },
                Some(c) => s.push(c),
                None => return None,
            }
        }
        out.push(s);
    }

    Some(out)
}
