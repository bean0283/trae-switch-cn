//! 进程内存扫描：从运行中的 Trae 客户端进程里提取 SQLCipher 加密密钥
//! （移植自 trae-session-export decrypt_tool/scan_memory.py，思路源自 wechat-decrypt）。
//!
//! 原理：
//!   1. 用 tasklist 找含 `ai_agent` 模块的客户端主进程（按内存占用取最大者）
//!   2. VirtualQueryEx 枚举全部 committed 可读内存区
//!   3. ReadProcessMemory 读回，在字节流里找 64 位十六进制密钥候选
//!   4. 用数据库第 1 页的盐 + HMAC-SHA512 逐候选验证（SQLCipher 4 的页面校验）
//!
//! 只支持 Windows（Trae 客户端密钥就藏在主进程内存里；macOS 方案不在本模块范围）。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha512;

const PAGE_SZ: usize = 4096;
const KEY_SZ: usize = 32;
const SALT_SZ: usize = 16;
const RESERVE_SZ: usize = 80;
const MEM_COMMIT: u32 = 0x1000;

/// 数据库首页信息（验证密钥用）。
#[derive(Debug, Clone)]
pub struct DbInfo {
    pub path: PathBuf,
    pub page1: Vec<u8>,
    pub salt_hex: String,
}

pub fn load_database_info(path: &Path) -> Option<DbInfo> {
    let mut f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    let mut page1 = vec![0u8; PAGE_SZ];
    let n = f.read(&mut page1).ok()?;
    if n < PAGE_SZ {
        return None;
    }
    let salt_hex = hex_encode(&page1[..SALT_SZ]);
    Some(DbInfo {
        path: path.to_path_buf(),
        page1,
        salt_hex,
    })
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn hex_char(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b)
}

/// 用 HMAC-SHA512 校验密钥候选（SQLCipher 4 页面 1 的校验结构）。
fn verify_enc_key(enc_key: &[u8], page1: &[u8]) -> bool {
    let salt = &page1[..SALT_SZ];
    let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ 0x3a).collect();
    let mut mac_key = [0u8; KEY_SZ];
    pbkdf2::pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);
    let hmac_data = &page1[SALT_SZ..PAGE_SZ - RESERVE_SZ + 16];
    let stored = &page1[PAGE_SZ - 64..];
    let mut mac = match Hmac::<Sha512>::new_from_slice(&mac_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(hmac_data);
    mac.update(&1u32.to_le_bytes());
    let digest = mac.finalize().into_bytes();
    digest.as_slice() == stored
}

// ---------------------------------------------------------------------------
// 进程定位
// ---------------------------------------------------------------------------

fn run_tasklist(args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("tasklist");
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    cmd.stdin(std::process::Stdio::null());
    let out = cmd.output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 该 pid 的进程是否加载了 ai_agent 模块（tasklist /M）。
fn has_ai_agent_module(pid: u32) -> bool {
    let filter = format!("PID eq {pid}");
    let out = run_tasklist(&["/FI", &filter, "/M", "/FO", "CSV", "/NH"]).unwrap_or_default();
    out.to_lowercase().contains("ai_agent")
}

/// 该客户端的进程镜像名（必须与所选客户端一一对应，避免拿别的客户端的
/// 内存去验证本客户端的库盐——那是「0 候选」的典型原因）。
pub fn process_names_for_client(client_key: &str) -> &'static [&'static str] {
    match client_key {
        "trae-cn" => &["Trae CN.exe"],
        "solo-cn" => &["TRAE SOLO CN.exe"],
        "trae-intl" => &["Trae.exe"],
        "solo-intl" => &["TRAE SOLO.exe"],
        _ => &["Trae CN.exe", "TRAE SOLO CN.exe", "Trae.exe", "TRAE SOLO.exe"],
    }
}

/// 找出该客户端加载了 ai_agent 模块的进程，返回 (pid, 内存KB)。
/// 与参考实现一致：内存降序取第一个命中者；都没有则退回内存最大者。
fn find_client_process(client_key: &str) -> Option<(u32, u64)> {
    let names = process_names_for_client(client_key);
    let mut pids: Vec<(u32, u64)> = Vec::new();
    for name in names {
        // 镜像名含空格（如 TRAE SOLO CN.exe）时值必须加双引号，否则 tasklist 过滤失败
        let filter = if name.contains(' ') {
            format!("IMAGENAME eq \"{name}\"")
        } else {
            format!("IMAGENAME eq {name}")
        };
        if let Some(out) = run_tasklist(&["/FI", &filter, "/FO", "CSV", "/NH"]) {
            for line in out.lines() {
                let line = line.trim().trim_matches('\0');
                if line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.splitn(3, ',').collect();
                if parts.len() < 2 {
                    continue;
                }
                let pid: u32 = parts[1].trim_matches('"').parse().unwrap_or(0);
                let mem: u64 = parts
                    .get(2)
                    .and_then(|s| s.trim_matches('"').split('K').next())
                    .and_then(|s| s.replace(',', "").trim().parse().ok())
                    .unwrap_or(0);
                if pid > 0 {
                    pids.push((pid, mem));
                }
            }
        }
    }
    pids.sort_by(|a, b| b.1.cmp(&a.1));
    for (pid, mem) in pids.iter() {
        if has_ai_agent_module(*pid) {
            return Some((*pid, *mem));
        }
    }
    pids.first().map(|(pid, mem)| (*pid, *mem))
}

// ---------------------------------------------------------------------------
// Windows 内存读取
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};

    const PROCESS_QUERY_INFORMATION: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0400);
    const PROCESS_VM_READ: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010);

    pub fn open(pid: u32) -> Option<HANDLE> {
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok() }
    }

    pub fn close(h: HANDLE) {
        unsafe {
            let _ = CloseHandle(h);
        }
    }

    /// 枚举 committed + 可读的内存区（单区 ≤500MB，与参考实现一致）。
    pub fn enum_regions(h: HANDLE) -> Vec<(u64, usize)> {
        let mut regions = Vec::new();
        let mut addr: u64 = 0;
        let max_addr: u64 = 0x7FFF_FFFF_FFFF;
        loop {
            if addr >= max_addr {
                break;
            }
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                VirtualQueryEx(
                    h,
                    Some(addr as *const std::ffi::c_void),
                    &mut mbi as *mut MEMORY_BASIC_INFORMATION,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if ret == 0 {
                break;
            }
            if mbi.State.0 == MEM_COMMIT {
                let protect = mbi.Protect.0;
                let readable = matches!(protect, 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80);
                if readable && mbi.RegionSize > 0 && mbi.RegionSize < 500 * 1024 * 1024 {
                    regions.push((mbi.BaseAddress as u64, mbi.RegionSize));
                }
            }
            let next = (mbi.BaseAddress as u64).wrapping_add(mbi.RegionSize as u64);
            if next <= addr {
                break;
            }
            addr = next;
        }
        regions
    }

    pub fn read_mem(h: HANDLE, addr: u64, size: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let mut read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                h,
                addr as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                Some(&mut read),
            )
        };
        if ok.is_ok() {
            buf.truncate(read);
            Some(buf)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// 扫描
// ---------------------------------------------------------------------------

/// 在内存块里找 SQLCipher 密钥候选并验证（语义对齐 scan_memory.py）。
///
/// 候选规则（比参考实现更彻底：全滑动窗口，密钥被更长 hex 段包裹也不会漏）：
///   · 任一位置起连续 64 个 hex 字符即为候选一，用数据库盐验证；
///   · 窗口向后延伸到 hex 段尾，段长 ≥96 且为偶数时，段末 32 为相邻盐，
///     盐与库盐一致才验证候选二（对应 x'...{64,192}'）。
fn scan_region(data: &[u8], base: u64, db: &DbInfo, candidates: &mut usize) -> Option<(String, u64)> {
    let salt_hex = db.salt_hex.as_bytes();
    let n = data.len();
    if n < 64 {
        return None;
    }
    let mut i = 0usize;
    while i + 64 <= n {
        let win = &data[i..i + 64];
        if !win.iter().all(|b| hex_char(*b)) {
            i += 1;
            continue;
        }
        // 候选一：密钥窗口 + 数据库盐（win 即 64 个 ASCII hex 字符，直接还原为密钥字节）
        *candidates += 1;
        let key_bytes = hex_to_bytes(win);
        if verify_enc_key(&key_bytes, &db.page1) {
            let key_hex = std::str::from_utf8(win)
                .map(str::to_string)
                .unwrap_or_else(|_| hex_encode(win));
            return Some((key_hex, base + i as u64));
        }
        // 候选二：相邻盐（对齐 pattern 1 的 {64,192} 上限）
        let mut j = i + 64;
        while j < n && hex_char(data[j]) {
            j += 1;
        }
        let eff_len = (j - i).min(192);
        if eff_len >= 96 && eff_len % 2 == 0 {
            let adj_salt = &data[i + eff_len - 32..i + eff_len];
            if adj_salt.len() == salt_hex.len() && adj_salt.eq_ignore_ascii_case(salt_hex) {
                *candidates += 1;
                let key_bytes = hex_to_bytes(&data[i..i + 64]);
                if verify_enc_key(&key_bytes, &db.page1) {
                    let key_hex = std::str::from_utf8(&data[i..i + 64])
                        .map(str::to_string)
                        .unwrap_or_else(|_| hex_encode(&data[i..i + 64]));
                    return Some((key_hex, base + i as u64));
                }
            }
        }
        i += 1; // 全滑动：密钥嵌在更长 hex 段中也能命中
    }
    None
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// 从十六进制字符序列还原密钥字节（容忍奇数长度，尾部截断）。
fn hex_to_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0usize;
    while i + 1 < b.len() {
        out.push((hex_val(b[i]) << 4) | hex_val(b[i + 1]));
        i += 2;
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub found: bool,
    pub key: Option<String>,
    pub address: Option<String>,
    pub candidates: usize,
    pub scanned_mb: u64,
    pub elapsed_ms: u64,
    pub pid: Option<u32>,
    pub message: String,
}

/// 扫描客户端进程内存，返回验证过的密钥（hex 字符串）。
/// `client_key` 决定扫描哪个客户端的进程（避免拿错进程的内存验证本库的盐）。
pub fn scan_for_key(
    client_key: &str,
    db_path: &Path,
    on_progress: Option<&dyn Fn(&str)>,
) -> Result<ScanResult, String> {
    let db = load_database_info(db_path).ok_or_else(|| {
        format!("无法读取数据库首页：{}", db_path.display())
    })?;

    #[cfg(not(windows))]
    {
        let _ = (db, on_progress);
        return Err("进程内存扫描仅支持 Windows".into());
    }

    #[cfg(windows)]
    {
        let t0 = Instant::now();
        let Some((pid, _mem)) = find_client_process(client_key) else {
            return Err(format!(
                "未检测到运行中的客户端进程（{}）。请先启动并登录后再扫描。",
                client_key
            ));
        };
        let h = win::open(pid).ok_or("无法打开客户端进程（权限不足？）")?;

        let regions = win::enum_regions(h);
        let total_bytes: u64 = regions.iter().map(|(_, s)| *s as u64).sum();
        if let Some(cb) = on_progress {
            cb(&format!(
                "进程 PID={pid}：{}MB / {} 个内存区，开始扫描…",
                total_bytes / 1024 / 1024,
                regions.len()
            ));
        }

        let mut candidates = 0usize;
        let mut scanned: u64 = 0;
        let mut read_fail = 0usize;
        let mut found: Option<(String, u64)> = None;
        for (idx, (base, size)) in regions.iter().enumerate() {
            if let Some(data) = win::read_mem(h, *base, *size) {
                scanned += data.len() as u64;
                if let Some(hit) = scan_region(&data, *base, &db, &mut candidates) {
                    found = Some(hit);
                    break;
                }
            } else {
                read_fail += 1;
            }
            if (idx + 1) % 100 == 0 && total_bytes > 0 {
                let pct = scanned as f64 * 100.0 / total_bytes as f64;
                if let Some(cb) = on_progress {
                    cb(&format!(
                        "已扫描 {:.1}% （{}MB，{} 个候选，读取失败 {} 区）",
                        pct,
                        scanned / 1024 / 1024,
                        candidates,
                        read_fail
                    ));
                }
            }
        }
        win::close(h);

        let elapsed_ms = t0.elapsed().as_millis() as u64;
        match found {
            Some((key, addr)) => Ok(ScanResult {
                found: true,
                key: Some(key),
                address: Some(format!("0x{addr:016X}")),
                candidates,
                scanned_mb: scanned / 1024 / 1024,
                elapsed_ms,
                pid: Some(pid),
                message: "已在进程内存中找到并验证密钥".to_string(),
            }),
            None => Ok(ScanResult {
                found: false,
                key: None,
                address: None,
                candidates,
                scanned_mb: scanned / 1024 / 1024,
                elapsed_ms,
                pid: Some(pid),
                message: "未在进程内存中找到有效密钥（客户端可能未运行或结构已变化）".to_string(),
            }),
        }
    }
}

/// 便捷：把验证过的密钥按客户端存盘，供解密/导出直接使用。
pub fn save_key(client_key: &str, key_hex: &str) -> Result<(), String> {
    let dir = crate::modules::config::store_dir().join("trae").join("keys");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{client_key}.json"));
    let payload = serde_json::json!({
        "client": client_key,
        "enc_key": key_hex,
        "saved_at": chrono::Local::now().to_rfc3339(),
    });
    std::fs::write(path, serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?)
        .map_err(|e| format!("写密钥文件失败: {e}"))?;
    Ok(())
}

/// 读取已存盘的密钥（hex 字符串）。
pub fn load_saved_key(client_key: &str) -> Option<String> {
    let path = crate::modules::config::store_dir()
        .join("trae")
        .join("keys")
        .join(format!("{client_key}.json"));
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("enc_key").and_then(|k| k.as_str()).map(String::from)
}

/// 临时诊断：读指定地址所在区域，搜索已知密钥字节并输出上下文。
#[cfg(windows)]
pub fn diag_read_at(client_key: &str, addr: u64, key_hex: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some((pid, _)) = find_client_process(client_key) else {
        out.push("未找到客户端进程".into());
        return out;
    };
    let h = match win::open(pid) {
        Some(h) => h,
        None => {
            out.push("打开进程失败".into());
            return out;
        }
    };
    let regions = win::enum_regions(h);
    let mut hit_region = None;
    for (base, size) in &regions {
        if *base <= addr && addr < *base + *size as u64 {
            hit_region = Some((*base, *size));
            break;
        }
    }
    let Some((base, size)) = hit_region else {
        out.push(format!("地址 0x{addr:X} 不在任何区域"));
        win::close(h);
        return out;
    };
    out.push(format!("区域 base=0x{base:X} size={size}"));
    match win::read_mem(h, base, size) {
        Some(data) => {
            let needle = key_hex.as_bytes();
            let off = (addr - base) as usize;
            let mut hit = None;
            if data.len() >= needle.len() {
                let mut i = 0usize;
                while i + needle.len() <= data.len() {
                    if &data[i..i + needle.len()] == needle {
                        hit = Some(i);
                        break;
                    }
                    i += 1;
                }
            }
            out.push(format!(
                "读取 OK {} 字节，目标偏移 {} 命中={:?}",
                data.len(),
                off,
                hit
            ));
            let ctx_s = off.saturating_sub(64);
            let ctx_e = (off + 96).min(data.len());
            out.push(format!(
                "上下文: {:?}",
                String::from_utf8_lossy(&data[ctx_s..ctx_e])
            ));
            // 顺便用滑动窗口验证：若命中，verify 结果？
            if let Some(hit_at) = hit {
                if let Some(info) = load_database_info(
                    std::path::Path::new(
                        r"C:\Users\11970\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent\database.db",
                    ),
                ) {
                    let ok = verify_enc_key(
                        &hex_to_bytes(&data[hit_at..hit_at + 64]),
                        &info.page1,
                    );
                    out.push(format!("verify(命中窗口) = {ok}"));
                }
            }
        }
        None => out.push("读取失败！".into()),
    }
    win::close(h);
    out
}
