//! GeneralZip 原生核心（cdylib）
//!
//! 职责边界：仅实现纯托管生态缺失的能力——7z 读写（含 AES-256 加密）、
//! RAR 解密读取（feature `rar`）、xz 编解码。经 C ABI 暴露给 C# 包装层。
//!
//! 边界纪律：
//! - 不跨边界抛异常：所有导出经 `catch_unwind` 兜底，返回状态码；
//! - 字符串 UTF-8 + 显式长度传递；口令经指针+长度传递（允许任意字节）；
//! - 错误详情经线程局部存储，由 `gzp_last_error` 读取。

mod caps;
mod codecs;
mod sevenz;
mod xz;

#[cfg(feature = "rar")]
mod rar;

/// 状态码：0 成功；负数为错误类别。
pub mod status {
    pub const OK: i32 = 0;
    pub const ERR_IO: i32 = -1;
    pub const ERR_FORMAT: i32 = -2;
    pub const ERR_PASSWORD: i32 = -3;
    pub const ERR_NOT_FOUND: i32 = -4;
    pub const ERR_UNSUPPORTED: i32 = -5;
    pub const ERR_PANIC: i32 = -6;
    pub const ERR_ARG: i32 = -7;
    pub const ERR_BUFFER: i32 = -8;
}

/// 进度回调：done/total 为未压缩累计字节。允许为 None。
pub type ProgressCb = Option<unsafe extern "system" fn(done: u64, total: u64, user: *mut std::os::raw::c_void)>;

/// 计数器：累计已处理未压缩字节并按节流间隔回调。
pub(crate) struct ProgressGate {
    cb: ProgressCb,
    user: *mut std::os::raw::c_void,
    done: u64,
    total: u64,
    last_report: u64,
}

// 进度指针对话仅在单次原生调用内使用（由 C# 侧保证串行）。
unsafe impl Send for ProgressGate {}

impl ProgressGate {
    pub fn new(cb: ProgressCb, user: *mut std::os::raw::c_void, total: u64) -> Self {
        Self { cb, user, done: 0, total, last_report: 0 }
    }

    pub fn advance(&mut self, delta: u64) {
        self.done = self.done.saturating_add(delta);
        // 每 64KB 或完成时回调一次，避免跨界洪泛
        if self.cb.is_some() && (self.done - self.last_report >= 65536 || self.done >= self.total) {
            self.last_report = self.done;
            unsafe {
                (self.cb.unwrap())(self.done, self.total, self.user);
            }
        }
    }

    pub fn done(&self) -> u64 {
        self.done
    }
}

/// 计数包装器：把读取字节量喂给 ProgressGate。
pub(crate) struct CountingReader<'a, R: std::io::Read> {
    inner: R,
    gate: &'a mut ProgressGate,
}

impl<'a, R: std::io::Read> CountingReader<'a, R> {
    pub fn new(inner: R, gate: &'a mut ProgressGate) -> Self {
        Self { inner, gate }
    }
}

impl<R: std::io::Read> std::io::Read for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.gate.advance(n as u64);
        }
        Ok(n)
    }
}

/// UTF-8 转义（JSON 字符串内使用）。
pub(crate) fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}
