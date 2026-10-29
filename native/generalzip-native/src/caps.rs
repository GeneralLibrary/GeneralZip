//! 版本、能力协商与线程局部错误详情。

use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

use crate::status;

/// 能力位。
pub mod capability {
    pub const SEVENZ: u32 = 1;
    pub const RAR: u32 = 2;
    pub const XZ: u32 = 4;
}

thread_local! {
    static LAST_ERROR: RefCell<String> = RefCell::new(String::new());
}

/// 记录线程局部错误详情。
pub fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
}

/// 读取并清空线程局部错误详情；返回写入长度（不含 NUL）。
#[no_mangle]
pub extern "system" fn gzp_last_error(buf: *mut u8, cap: u32) -> c_int {
    if buf.is_null() || cap == 0 {
        return 0;
    }

    let msg = LAST_ERROR.with(|e| std::mem::take(&mut *e.borrow_mut()));
    let bytes = msg.as_bytes();
    let n = bytes.len().min(cap as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
        *buf.add(n) = 0;
    }
    n as c_int
}

/// 组件版本（UTF-8 静态字符串）。
#[no_mangle]
pub extern "system" fn gzp_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// 能力位图：bit0=7z, bit1=rar, bit2=xz。
#[no_mangle]
pub extern "system" fn gzp_capabilities() -> u32 {
    let mut caps = capability::SEVENZ;
    #[cfg(feature = "rar")]
    {
        caps |= capability::RAR;
    }
    caps |= capability::XZ;
    caps
}

/// 释放原生分配的内存。
#[no_mangle]
pub extern "system" fn gzp_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { drop(std::boxed::Box::from_raw(ptr)) };
    }
}

/// C 字符串 → &str（非法 UTF-8 报参数错误）。
pub(crate) fn str_from_c_ptr<'a>(ptr: *const c_char) -> Result<&'a str, c_int> {
    if ptr.is_null() {
        set_error("path 参数为空");
        return Err(status::ERR_ARG);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| {
            set_error("path 不是合法 UTF-8");
            status::ERR_ARG
        })
}

/// 指针+长度口令 → String（UTF-8；空指针/零长 = 无口令）。
pub(crate) fn password_from_ptr(ptr: *const u8, len: u32) -> Option<String> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// 统一把 anyhow 风格错误映射为状态码。
pub(crate) fn map_error(err: &dyn std::fmt::Display) -> c_int {
    let text = err.to_string();
    set_error(text);
    status::ERR_IO
}
