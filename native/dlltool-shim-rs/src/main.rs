//! dlltool 垫片（构建辅助工具）：把 rustc 的 GNU dlltool 调用转译为 rust-lld
//! （lld-link /DEF 模式），用于 windows-gnu 目标上 raw-dylib 导入库的生成。
//!
//! 安全说明：本程序为仓库内构建辅助工具，仅在构建机上由 rustc 调用自身；
//! 输入（def/out 路径）全部来自 rustc 传给本工具的参数，不来自任何外部用户；
//! 子进程经 `std::process::Command` 逐参数传递（不经 shell、自动转义）。
//!
//! 用法（rustc 传入形如）：
//!   gzdlltool -d <def文件> -D <dll名> -l <输出.lib> -m i386:x86-64 --64 ...

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut def: Option<String> = None;
    let mut out_lib: Option<String> = None;
    let mut dll_name: Option<String> = None;

    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-d" => def = iter.next().cloned(),
            "-l" => out_lib = iter.next().cloned(),
            "-D" => dll_name = iter.next().cloned(),
            // 以下 dlltool 参数对本转译无意义，跳过（含其值）
            "-m" | "-f" | "--temp-prefix" => {
                iter.next();
            }
            _ => {}
        }
    }

    let Some(def_in) = def else {
        eprintln!("gzdlltool: missing -d argument");
        std::process::exit(1);
    };
    let Some(out_lib) = out_lib else {
        eprintln!("gzdlltool: missing -l argument");
        std::process::exit(1);
    };

    // 纵深防御：拒绝控制字符与引号/元字符，保证子进程参数不可能被二次解析
    assert_safe_argument("-d", &def_in);
    assert_safe_argument("-l", &out_lib);
    if let Some(dll) = &dll_name {
        assert_safe_argument("-D", dll);
    }

    // def 文件确保有 LIBRARY 行（lld-link 需要）；必要时写 patched 副本
    let mut def_path = PathBuf::from(&def_in);
    let def_text = fs::read_to_string(&def_path).unwrap_or_default();
    if !def_text.trim_start().to_uppercase().starts_with("LIBRARY") {
        let dll_stem = dll_name
            .as_deref()
            .map(Path::new)
            .and_then(|p| p.file_stem())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "library".to_string());
        let patched = Path::new(out_lib.as_str())
            .with_file_name(format!("{}.patched.def", Path::new(&out_lib).file_stem().map(|s| s.to_string_lossy()).unwrap_or_default()));
        fs::write(&patched, format!("LIBRARY \"{dll_stem}\"\n{def_text}").as_bytes())
            .expect("gzdlltool: failed to write patched.def");
        def_path = patched;
    }
    let def_display = def_path.to_string_lossy().into_owned();
    let out_display = PathBuf::from(&out_lib).to_string_lossy().into_owned();

    let lld = find_rust_lld().unwrap_or_else(|| {
        eprintln!("gzdlltool: rust-lld.exe not found (add the rustup toolchain bin directory to PATH)");
        std::process::exit(1);
    });

    let mut lld_args: Vec<String> = vec!["-flavor".into(), "link".into()];
    let mut def_arg = String::from("/DEF:");
    def_arg.push_str(&def_display);
    let mut out_arg = String::from("/OUT:");
    out_arg.push_str(&out_display);
    lld_args.push(def_arg);
    lld_args.push(out_arg);
    lld_args.push("/MACHINE:X64".into());
    lld_args.push("/NOLOGO".into());

    let status = Command::new(lld).args(&lld_args).status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("gzdlltool: rust-lld exited with code {s}");
            std::process::exit(s.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("gzdlltool: failed to start rust-lld: {e}");
            std::process::exit(1);
        }
    }
}

fn find_rust_lld() -> Option<PathBuf> {
    let home = std::env::var("USERPROFILE").ok()?;
    let root = Path::new(&home).join(".rustup").join("toolchains");
    let entries = fs::read_dir(&root).ok()?;

    for entry in entries.flatten() {
        let candidate = entry
            .path()
            .join("lib")
            .join("rustlib")
            .join("x86_64-pc-windows-gnu")
            .join("bin")
            .join("rust-lld.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

/// 纵深防御：拒绝控制字符与引号/shell 元字符（合法路径不含这些字符；
/// 路径分隔符 / 与 \ 不受影响）。本工具经 Command 逐参数传递、不经 shell，
/// 本不存在注入；此校验进一步保证任何参数字符都无法改变子进程参数边界。
fn assert_safe_argument(option: &str, value: &str) {
    for ch in value.chars() {
        let is_forbidden = ch.is_control()
            || matches!(
                ch,
                '"' | '\'' | '`' | '$' | '|' | '&' | ';' | '<' | '>' | '%' | '*'
                    | '?' | '!' | '(' | ')' | '{' | '}'
            );
        if is_forbidden {
            eprintln!("gzdlltool: argument {option} contains illegal character {ch:?}; rejected");
            std::process::exit(1);
        }
    }
}
