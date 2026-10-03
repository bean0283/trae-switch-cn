//! SQLCipher 4 数据库页面级解密（移植自 trae-session-export decrypt_tool/decrypt_db.py）。
//!
//! Trae 的会话数据库 `database.db` 用 SQLCipher 4 加密：
//!   AES-256-CBC、HMAC-SHA512、reserve=80、page_size=4096
//! 密钥来源：`trae_memory_scan` 从客户端进程内存中提取并验证。
//!
//! 解密输出为普通 SQLite 文件，之后用 rusqlite 读取统计表与行数。

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use serde::Serialize;
use sha2::Sha512;

use crate::modules::trae_km::aes_cbc_decrypt;

const PAGE_SZ: usize = 4096;
const KEY_SZ: usize = 32;
const SALT_SZ: usize = 16;
const IV_SZ: usize = 16;
const HMAC_SZ: usize = 64;
const RESERVE_SZ: usize = 80;
const SQLITE_HDR: &[u8] = b"SQLite format 3\x00";

#[derive(Debug, Clone, Serialize)]
pub struct TableStat {
    pub name: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecryptReport {
    pub out_path: String,
    pub pages: u64,
    pub total_bytes: u64,
    pub elapsed_ms: u64,
    pub hmac_ok: bool,
    pub tables: Vec<TableStat>,
}

pub(crate) fn derive_mac_key(enc_key: &[u8], salt: &[u8]) -> [u8; KEY_SZ] {
    let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ 0x3a).collect();
    let mut mac_key = [0u8; KEY_SZ];
    pbkdf2::pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);
    mac_key
}

/// 校验第 1 页的 HMAC-SHA512（密钥正确性判据）。
pub fn verify_page1_hmac(enc_key: &[u8], page1: &[u8]) -> bool {
    if page1.len() < PAGE_SZ {
        return false;
    }
    use hmac::{Hmac, Mac};
    let salt = &page1[..SALT_SZ];
    let mac_key = derive_mac_key(enc_key, salt);
    let hmac_data = &page1[SALT_SZ..PAGE_SZ - RESERVE_SZ + IV_SZ];
    let stored = &page1[PAGE_SZ - HMAC_SZ..];
    let mut mac = match Hmac::<Sha512>::new_from_slice(&mac_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(hmac_data);
    mac.update(&1u32.to_le_bytes());
    let digest = mac.finalize().into_bytes();
    digest.as_slice() == stored
}

/// 解密单个页面。
pub(crate) fn decrypt_page(enc_key: &[u8], page: &[u8], pgno: u64) -> Vec<u8> {
    let iv = &page[PAGE_SZ - RESERVE_SZ..PAGE_SZ - RESERVE_SZ + IV_SZ];
    let mut iv_arr = [0u8; IV_SZ];
    iv_arr.copy_from_slice(iv);
    let plain = if pgno == 1 {
        let encrypted = &page[SALT_SZ..PAGE_SZ - RESERVE_SZ];
        let mut out = Vec::with_capacity(PAGE_SZ);
        out.extend_from_slice(SQLITE_HDR);
        out.extend_from_slice(&aes_cbc_decrypt::<aes::Aes256>(enc_key, &iv_arr, encrypted));
        out
    } else {
        let encrypted = &page[..PAGE_SZ - RESERVE_SZ];
        aes_cbc_decrypt::<aes::Aes256>(enc_key, &iv_arr, encrypted)
    };
    let mut out = plain;
    out.resize(PAGE_SZ, 0);
    out
}

/// 解密整个数据库。`enc_key_hex` 为 64 位 hex 密钥。
/// 返回解密报告（含表名与行数，供前端展示与导出模块使用）。
pub fn decrypt_database(
    db_path: &Path,
    enc_key_hex: &str,
    out_path: &Path,
    on_progress: Option<&dyn Fn(&str)>,
) -> Result<DecryptReport, String> {
    if enc_key_hex.trim().len() != 64 {
        return Err("密钥必须是 64 位十六进制字符串".into());
    }
    let enc_key = hex_to_bytes(enc_key_hex.trim());
    let t0 = std::time::Instant::now();

    let mut fin = std::fs::File::open(db_path).map_err(|e| format!("打开数据库失败: {e}"))?;
    let mut page1 = vec![0u8; PAGE_SZ];
    fin.read_exact(&mut page1)
        .map_err(|e| format!("读取数据库首页失败: {e}"))?;

    if !verify_page1_hmac(&enc_key, &page1) {
        return Err("HMAC 校验失败：密钥与数据库不匹配（可能密钥过期或客户端已重新登录）".into());
    }

    let file_size = fin
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("读取文件大小失败: {e}"))?;
    fin.seek(SeekFrom::Start(0))
        .map_err(|e| format!("定位失败: {e}"))?;

    let total_pages = file_size.div_ceil(PAGE_SZ as u64);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建输出目录失败: {e}"))?;
    }
    let mut fout = std::fs::File::create(out_path).map_err(|e| format!("创建输出文件失败: {e}"))?;

    let mut page = vec![0u8; PAGE_SZ];
    let mut pgno: u64 = 1;
    loop {
        let n = fin.read(&mut page).map_err(|e| format!("读取页面失败: {e}"))?;
        if n == 0 {
            break;
        }
        if n < PAGE_SZ {
            page.resize(PAGE_SZ, 0);
        }
        let dec = decrypt_page(&enc_key, &page, pgno);
        fout.write_all(&dec).map_err(|e| format!("写入失败: {e}"))?;
        page.resize(PAGE_SZ, 0);
        pgno += 1;
        if pgno % 10000 == 0 {
            if let Some(cb) = on_progress {
                cb(&format!("解密进度：{}/{} 页", pgno - 1, total_pages));
            }
        }
    }
    let _ = fout.flush();

    let elapsed_ms = t0.elapsed().as_millis() as u64;

    // 用 rusqlite 打开解密后的库，统计表与行数（同时充当解密有效性验证）
    let tables = list_tables(out_path);
    Ok(DecryptReport {
        out_path: out_path.to_string_lossy().into_owned(),
        pages: total_pages,
        total_bytes: file_size,
        elapsed_ms,
        hmac_ok: true,
        tables,
    })
}

/// 列出解密库中的表及行数。
pub fn list_tables(db_path: &Path) -> Vec<TableStat> {
    let mut out = Vec::new();
    let Ok(conn) = rusqlite::Connection::open(db_path) else {
        return out;
    };
    let mut stmt = match conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map(|it| it.filter_map(Result::ok).collect())
        .unwrap_or_default();
    drop(stmt);
    for name in names {
        let count = conn
            .query_row(&format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")), [], |r| r.get(0))
            .unwrap_or(0);
        out.push(TableStat { name, count });
    }
    out
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

pub(crate) fn hex_to_bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| (hex_val(c[0]) << 4) | hex_val(c[1]))
        .collect()
}
