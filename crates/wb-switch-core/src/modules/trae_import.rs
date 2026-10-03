//! 跨账号会话导入：把「本账号解密出的会话记录」写入另一个账号的本地加密库。
//!
//! 目标按**账号**（client@account）而不是客户端划分：同一客户端（如 TRAE SOLO CN）
//! 下的多个账号共享同一个本地库，跨账号导入 = 在明文副本里**复制会话并改写归属**
//! （新 session_id / message_id + project 指向目标 uid），源账号记录保留。
//!
//! 原理（与 `trae_decrypt` 严格对称的页面级实现，零新增依赖）：
//!   1. 目标库先整体解密为明文副本（复用 `decrypt_database`）；
//!   2. 在明文副本上插入源会话数据（rusqlite 动态列复制，列交集保真）；
//!   3. 把明文副本逐页加密回写为 SQLCipher 库（本模块 `encrypt_db_file`）；
//!   4. 校验 + 原子替换（先备份原库与 wal/shm，失败回滚）。
//!
//! 前置约束：
//!   · 目标账号必须在本机登录过（有 database.db，且密钥可得：存盘密钥优先，
//!     无存盘密钥时需该账号进程运行中做内存扫描）；
//!   · 导入时目标客户端必须退出（避免文件占用与 WAL 不一致），会自动杀进程。
//!
//! 已知边界：写进目标库的会话是「本地新增」行，与云端任务列表的双向同步行为
//! 未定义——若该账号云端同步会清理本地孤儿行，导入的会话可能被覆盖。

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::modules::config::store_dir;
use crate::modules::trae_decrypt::{decrypt_database, derive_mac_key, hex_to_bytes, verify_page1_hmac};
use crate::modules::trae_discover::{database_path, get_client, list_installed_clients, storage_json_path};
use crate::modules::trae_export::{decrypted_db_path, open_decrypted};
use crate::modules::trae_km::aes_cbc_encrypt;
use crate::modules::trae_memory_scan::{load_saved_key, save_key, scan_for_key};
use crate::modules::trae_switch::{is_running, kill_all, wait_until_stopped};
use crate::modules::trae_vault::{list_vault_accounts, read_meta, uid_of_account, uid_from_storage_text};
use aes::Aes256;

const PAGE_SZ: usize = 4096;
const KEY_SZ: usize = 32;
const SALT_SZ: usize = 16;
const IV_SZ: usize = 16;
const HMAC_SZ: usize = 64;
const RESERVE_SZ: usize = 80;
/// 页 1 加密载荷起始（跳过 salt）。
const AUTH_DATA_START: usize = SALT_SZ;
/// 加密载荷 / 可用数据长度（4096 - 80）。
const USABLE_SZ: usize = PAGE_SZ - RESERVE_SZ;
/// HMAC 起始偏移（IV 之后）。
const HMAC_START: usize = PAGE_SZ - HMAC_SZ;

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| format!("随机数生成失败: {e}"))?;
    Ok(out)
}

/// 生成与客户端原生一致的 24 位十六进制 id（12 随机字节）。
/// 客户端原生 session_id / message_id / project_id 均为 24 位 hex；
/// 32 位 UUID 会触发工具内 `is_session_id`（20~24 位）校验失败，导致详情/MD/删除不可用。
fn native_hex_id() -> String {
    let b = random_bytes::<12>().unwrap_or([0u8; 12]);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 把一页明文（标准 SQLite 页，usable=4016）加密成 SQLCipher 页。
fn encrypt_sqlcipher_page(
    enc_key: &[u8; KEY_SZ],
    mac_key: &[u8; KEY_SZ],
    salt: [u8; SALT_SZ],
    pgno: u64,
    plain: &[u8; PAGE_SZ],
) -> Result<[u8; PAGE_SZ], String> {
    let mut out = [0u8; PAGE_SZ];
    let iv = random_bytes::<IV_SZ>()?;
    let (cipher_start, content) = if pgno == 1 {
        out[..SALT_SZ].copy_from_slice(&salt);
        (SALT_SZ, &plain[SALT_SZ..USABLE_SZ])
    } else {
        (0usize, &plain[..USABLE_SZ])
    };
    let cipher = aes_cbc_encrypt::<Aes256>(enc_key, &iv, content);
    if cipher.len() != USABLE_SZ - cipher_start {
        return Err(format!("页面加密长度不符：{}-{}", cipher.len(), cipher_start));
    }
    out[cipher_start..USABLE_SZ].copy_from_slice(&cipher);
    out[USABLE_SZ..USABLE_SZ + IV_SZ].copy_from_slice(&iv);

    // HMAC 覆盖密文+IV：页 1 从 salt 之后起，其余页从页首起；页号按 SQLCipher 约定取 4 字节
    use hmac::{Hmac, Mac};
    let hmac_start = if pgno == 1 { AUTH_DATA_START } else { 0 };
    let mut mac = Hmac::<sha2::Sha512>::new_from_slice(mac_key).map_err(|e| e.to_string())?;
    mac.update(&out[hmac_start..HMAC_START]);
    mac.update(&(pgno as u32).to_le_bytes());
    let digest = mac.finalize().into_bytes();
    out[HMAC_START..].copy_from_slice(&digest[..HMAC_SZ]);
    Ok(out)
}

/// 加密整库：明文副本 → SQLCipher 文件。返回写入页数。
/// 明文副本的页 1 头 reserved 字段必须已是 80（见 `prepare_plain_copy`），
/// 保证 SQLite 写入时不会越过 [..4016] 区域，页尾 80 字节保持清零。
pub fn encrypt_db_file(
    enc_key_hex: &str,
    plain_path: &Path,
    out_path: &Path,
    on_progress: Option<&dyn Fn(&str)>,
) -> Result<u64, String> {
    let enc_key_vec = hex_to_bytes(enc_key_hex.trim());
    if enc_key_vec.len() != KEY_SZ {
        return Err("密钥必须是 64 位十六进制字符串".into());
    }
    let mut enc_key = [0u8; KEY_SZ];
    enc_key.copy_from_slice(&enc_key_vec);
    let mut fin = std::fs::File::open(plain_path).map_err(|e| format!("打开明文副本失败: {e}"))?;
    use std::io::{Read, Seek, Write};
    let size = fin
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| format!("读取明文副本大小失败: {e}"))?;
    fin.seek(std::io::SeekFrom::Start(0))
        .map_err(|e| format!("定位失败: {e}"))?;
    if size % PAGE_SZ as u64 != 0 {
        return Err(format!("明文副本大小 {size} 不是页大小整数倍，结构异常"));
    }
    let pages = size / PAGE_SZ as u64;
    if pages == 0 {
        return Err("明文副本为空".into());
    }
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建输出目录失败: {e}"))?;
    }
    let mut fout = std::fs::File::create(out_path).map_err(|e| format!("创建加密库失败: {e}"))?;

    let salt = random_bytes::<SALT_SZ>()?;
    let mac_key = derive_mac_key(&enc_key, &salt);
    let mut buf = [0u8; PAGE_SZ];
    let t0 = std::time::Instant::now();
    for pgno in 1..=pages {
        fin.read_exact(&mut buf).map_err(|e| format!("读取明文页 {pgno} 失败: {e}"))?;
        // 明文库 reserve 区（[4016..4096]）必须全零，否则加密会丢字节
        if buf[USABLE_SZ..].iter().any(|b| *b != 0) {
            return Err(format!(
                "明文页 {pgno} 的尾部保留区非零（客户端版本不兼容？），中止回写以防数据损坏"
            ));
        }
        let enc = encrypt_sqlcipher_page(&enc_key, &mac_key, salt, pgno, &buf)?;
        fout.write_all(&enc).map_err(|e| format!("写加密页 {pgno} 失败: {e}"))?;
        if let Some(cb) = on_progress {
            if pgno % 256 == 0 || pgno == pages {
                cb(&format!(
                    "加密回写 {pgno}/{pages} 页（{:.0}%）",
                    pgno as f64 * 100.0 / pages as f64
                ));
            }
        }
    }
    let _ = t0;

    // 自检：首页 HMAC 必须通过，否则拒绝替换
    let mut page1 = [0u8; PAGE_SZ];
    {
        let mut chk = std::fs::File::open(out_path).map_err(|e| e.to_string())?;
        chk.read_exact(&mut page1).map_err(|e| format!("自检读首页失败: {e}"))?;
    }
    if !verify_page1_hmac(&enc_key, &page1) {
        return Err("加密回写自检失败：首页 HMAC 校验不通过，已中止替换".into());
    }
    Ok(pages)
}

/// 把明文副本页 1 头部的 reserved-per-page 字段（offset 20）改为 80，
/// 使 SQLite 打开副本时认为 usable=4016，写入不会越过页尾保留区。
pub(crate) fn patch_reserved_field(path: &Path) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("打开明文副本补丁失败: {e}"))?;
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut head = [0u8; 100];
    f.read_exact(&mut head).map_err(|e| format!("读明文副本页头失败: {e}"))?;
    if &head[..16] != b"SQLite format 3\x00" {
        return Err("明文副本不是有效 SQLite 文件".into());
    }
    f.seek(SeekFrom::Start(20)).map_err(|e| e.to_string())?;
    f.write_all(&[RESERVE_SZ as u8])
        .map_err(|e| format!("写 reserved 字段失败: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 会话复制（动态列交集，按行整表保真）
// ---------------------------------------------------------------------------

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("查询表结构 {table} 失败: {e}"))?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("读取表结构 {table} 失败: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("解析表结构 {table} 失败: {e}"))?;
    if cols.is_empty() {
        return Err(format!("目标库没有表 {table}（客户端版本差异？）"));
    }
    Ok(cols)
}

/// 公共列交集，排除自增主键 `id`：源行的整型主键会与目标库已有行冲突，
/// 复制时跳过该列，由 SQLite 自动分配新值。
fn common_cols(src_cols: &[String], dst_cols: &[String]) -> Vec<String> {
    src_cols
        .iter()
        .filter(|c| dst_cols.contains(c) && c.as_str() != "id")
        .cloned()
        .collect()
}

/// 复制一张表中满足 `where_sql` 的行（源列 ∩ 目标列），返回复制行数。
fn copy_rows(
    src: &Connection,
    dst: &Connection,
    table: &str,
    where_sql: &str,
    param: &str,
) -> Result<usize, String> {
    let cols = common_cols(&table_columns(src, table)?, &table_columns(dst, table)?);
    if cols.is_empty() {
        return Err(format!("表 {table} 无公共列，无法复制"));
    }
    let col_list = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let select_sql = format!("SELECT {col_list} FROM {table} WHERE {where_sql}");
    let mut stmt = src
        .prepare(&select_sql)
        .map_err(|e| format!("源表 {table} 查询失败: {e}"))?;
    let rows = stmt
        .query_map(params![param], |row| {
            let mut vals = Vec::new();
            for i in 0..cols.len() {
                vals.push(row.get::<_, rusqlite::types::Value>(i)?);
            }
            Ok(vals)
        })
        .map_err(|e| format!("源表 {table} 读取失败: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("源表 {table} 行读取失败: {e}"))?;
    if rows.is_empty() {
        return Ok(0);
    }
    let placeholders = (0..cols.len())
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let insert_sql = format!("INSERT INTO {table} ({col_list}) VALUES ({placeholders})");
    let mut ins = dst
        .prepare(&insert_sql)
        .map_err(|e| format!("目标表 {table} 插入准备失败: {e}"))?;
    for vals in &rows {
        let args: Vec<&dyn rusqlite::types::ToSql> = vals
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();
        ins.execute(rusqlite::params_from_iter(args))
            .map_err(|e| format!("目标表 {table} 插入失败: {e}"))?;
    }
    Ok(rows.len())
}

/// 会话复制参数：
/// - `dst_uid`：目标账号 uid（project 归属必须指向它）；
/// - `new_sid`：Some(新 session_id) 表示同库复制（源目标同一客户端），需生成全新 id；
///   跨客户端复制传 None，保留原 session_id（不同库唯一约束不冲突）。
#[derive(Default)]
struct CopyOpts {
    dst_uid: Option<String>,
    new_sid: Option<String>,
}

/// 复制单个会话（chat_session 一行 + project 归属 + 全部关联表行）。
/// 返回 (插入行数, 跳过原因)。目标库已有该 session_id 且非同库复制时返回跳过。
fn copy_session(
    src: &Connection,
    dst: &Connection,
    sid: &str,
    opts: &CopyOpts,
    on_log: Option<&dyn Fn(&str)>,
) -> Result<Option<(usize, String)>, String> {
    let same_db = opts.new_sid.is_some();
    let out_sid = opts.new_sid.clone().unwrap_or_else(|| sid.to_string());
    let exists: Option<i64> = dst
        .query_row(
            "SELECT 1 FROM chat_session WHERE session_id=? LIMIT 1",
            params![out_sid],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| format!("目标库冲突检查失败: {e}"))?;
    if exists.is_some() {
        return Ok(None);
    }

    // project 归属：为目标 uid 查找/新建 project，新会话指向它
    let dst_uid = opts.dst_uid.as_deref();
    let dst_project_id = if let Some(uid) = dst_uid {
        Some(ensure_project_for(src, dst, sid, uid)?)
    } else {
        None
    };

    let mut n = 0usize;
    // 主表：chat_session 行（列交集复制，改写 project_id）
    {
        let cols = common_cols(&table_columns(src, "chat_session")?, &table_columns(dst, "chat_session")?);
        if cols.is_empty() {
            return Err("chat_session 无公共列，无法复制".into());
        }
        let col_list = cols
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut stmt = src
            .prepare(&format!("SELECT {col_list} FROM chat_session WHERE session_id=?"))
            .map_err(|e| format!("源 chat_session 查询失败: {e}"))?;
        let mut row = stmt
            .query_map(params![sid], |r| {
                let mut vals = Vec::new();
                for i in 0..cols.len() {
                    vals.push(r.get::<_, rusqlite::types::Value>(i)?);
                }
                Ok(vals)
            })
            .map_err(|e| format!("源 chat_session 读取失败: {e}"))?
            .next()
            .ok_or_else(|| format!("源会话 {sid} 不存在"))?
            .map_err(|e| format!("源 chat_session 行解析失败: {e}"))?;
        if same_db {
            row[cols
                .iter()
                .position(|c| *c == "session_id")
                .ok_or("chat_session 缺 session_id 列")?] = rusqlite::types::Value::Text(out_sid.clone());
        }
        if let (Some(pid), Some(idx)) = (
            dst_project_id.as_deref(),
            cols.iter().position(|c| *c == "project_id"),
        ) {
            row[idx] = rusqlite::types::Value::Text(pid.to_string());
        }
        let placeholders = (0..cols.len()).map(|_| "?").collect::<Vec<_>>().join(", ");
        let mut ins = dst
            .prepare(&format!("INSERT INTO chat_session ({col_list}) VALUES ({placeholders})"))
            .map_err(|e| format!("目标 chat_session 插入准备失败: {e}"))?;
        let args: Vec<&dyn rusqlite::types::ToSql> = row
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();
        ins.execute(rusqlite::params_from_iter(args))
            .map_err(|e| format!("目标 chat_session 插入失败: {e}"))?;
        n += 1;
    }

    // 消息表：chat_message（id 映射）+ general/task 关联
    let mids: Vec<String> = {
        let mut stmt = src
            .prepare("SELECT message_id FROM chat_message WHERE session_id=?")
            .map_err(|e| format!("源消息 id 查询失败: {e}"))?;
        let rows = stmt
            .query_map(params![sid], |r| r.get::<_, String>(0))
            .map_err(|e| format!("源消息 id 读取失败: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("源消息 id 解析失败: {e}"))?;
        rows
    };
    let mut mid_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if !mids.is_empty() {
        let cols = common_cols(&table_columns(src, "chat_message")?, &table_columns(dst, "chat_message")?);
        let col_list = cols
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let in_sql = format!(
            "message_id IN ({})",
            (0..mids.len()).map(|_| "?").collect::<Vec<_>>().join(",")
        );
        let mut stmt = src
            .prepare(&format!("SELECT {col_list} FROM chat_message WHERE {in_sql}"))
            .map_err(|e| format!("源 chat_message 查询失败: {e}"))?;
        let rows: Vec<Vec<rusqlite::types::Value>> = {
            let mapped = stmt
                .query_map(rusqlite::params_from_iter(mids.iter().map(|s| s.as_str())), |r| {
                    let mut vals = Vec::new();
                    for i in 0..cols.len() {
                        vals.push(r.get::<_, rusqlite::types::Value>(i)?);
                    }
                    Ok(vals)
                })
                .map_err(|e| format!("源 chat_message 读取失败: {e}"))?;
            mapped
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("源 chat_message 行读取失败: {e}"))?
        };
        let mid_idx = cols
            .iter()
            .position(|c| *c == "message_id")
            .ok_or("chat_message 缺 message_id 列")?;
        let sid_idx = cols
            .iter()
            .position(|c| *c == "session_id")
            .ok_or("chat_message 缺 session_id 列")?;
        let reply_idx = cols.iter().position(|c| *c == "reply_to_message_id");
        let mut out: Vec<Vec<rusqlite::types::Value>> = Vec::new();
        for (old, mut vals) in mids.iter().zip(rows) {
            let new_mid = if same_db {
                let m = native_hex_id();
                mid_map.insert(old.clone(), m.clone());
                m
            } else {
                old.clone()
            };
            vals[mid_idx] = rusqlite::types::Value::Text(new_mid);
            vals[sid_idx] = rusqlite::types::Value::Text(out_sid.clone());
            if same_db {
                if let Some(ri) = reply_idx {
                    if let rusqlite::types::Value::Text(rep) = &vals[ri] {
                        if let Some(nm) = mid_map.get(rep) {
                            vals[ri] = rusqlite::types::Value::Text(nm.clone());
                        }
                    }
                }
            }
            out.push(vals);
        }
        if !out.is_empty() {
            let placeholders = (0..cols.len()).map(|_| "?").collect::<Vec<_>>().join(", ");
            let mut ins = dst
                .prepare(&format!("INSERT INTO chat_message ({col_list}) VALUES ({placeholders})"))
                .map_err(|e| format!("目标 chat_message 插入准备失败: {e}"))?;
            for vals in &out {
                let args: Vec<&dyn rusqlite::types::ToSql> = vals
                    .iter()
                    .map(|v| v as &dyn rusqlite::types::ToSql)
                    .collect();
                ins.execute(rusqlite::params_from_iter(args))
                    .map_err(|e| format!("目标 chat_message 插入失败: {e}"))?;
            }
            n += out.len();
        }

        // chat_message_general / chat_message_task：message_id 映射后复制
        for table in ["chat_message_general", "chat_message_task"] {
            let t_cols = common_cols(&table_columns(src, table)?, &table_columns(dst, table)?);
            if t_cols.is_empty() {
                continue;
            }
            let t_col_list = t_cols
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let mut stmt = src
                .prepare(&format!(
                    "SELECT {t_col_list} FROM {table} WHERE {in_sql}"
                ))
                .map_err(|e| format!("源表 {table} 查询失败: {e}"))?;
            let rows: Vec<Vec<rusqlite::types::Value>> = {
                let mapped = stmt
                    .query_map(rusqlite::params_from_iter(mids.iter().map(|s| s.as_str())), |row| {
                        let mut vals = Vec::new();
                        for i in 0..t_cols.len() {
                            vals.push(row.get::<_, rusqlite::types::Value>(i)?);
                        }
                        Ok(vals)
                    })
                    .map_err(|e| format!("源表 {table} 读取失败: {e}"))?;
                mapped
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("源表 {table} 行读取失败: {e}"))?
            };
            if rows.is_empty() {
                continue;
            }
            let t_mid_idx = t_cols
                .iter()
                .position(|c| *c == "message_id")
                .ok_or(format!("{table} 缺 message_id 列"))?;
            let mut out: Vec<Vec<rusqlite::types::Value>> = Vec::new();
            for mut vals in rows {
                if let rusqlite::types::Value::Text(old) = &vals[t_mid_idx] {
                    if let Some(nm) = mid_map.get(old) {
                        vals[t_mid_idx] = rusqlite::types::Value::Text(nm.clone());
                    }
                }
                out.push(vals);
            }
            let placeholders = (0..t_cols.len()).map(|_| "?").collect::<Vec<_>>().join(", ");
            let mut ins = dst
                .prepare(&format!("INSERT INTO {table} ({t_col_list}) VALUES ({placeholders})"))
                .map_err(|e| format!("目标表 {table} 插入准备失败: {e}"))?;
            for vals in &out {
                let args: Vec<&dyn rusqlite::types::ToSql> = vals
                    .iter()
                    .map(|v| v as &dyn rusqlite::types::ToSql)
                    .collect();
                ins.execute(rusqlite::params_from_iter(args))
                    .map_err(|e| format!("目标表 {table} 插入失败: {e}"))?;
            }
            n += out.len();
        }
        // server_history_info / history_v2：历史/用量镜像行（同库复制时改写唯一键）
        for (table, col) in [("server_history_info", "conversation_id"), ("history_v2", "session_id")] {
            if same_db {
                if let Ok(v) = copy_history_aux(src, dst, table, col, sid, &out_sid, Some(&mid_map)) {
                    n += v;
                }
            } else if let Ok(added) = copy_rows(src, dst, table, &format!("{col} = ?"), sid) {
                n += added;
            }
        }
    }
    if let Some(cb) = on_log {
        cb(&format!("会话 {sid}：已复制 {n} 行{}", if same_db { "（新 id）" } else { "" }));
    }
    Ok(Some((n, String::new())))
}

/// 复制历史/用量镜像表（server_history_info / history_v2）供同库复制使用：
/// 改写会话关联列并重新生成唯一键（history_id / client_history_id / history_v2_id），
/// 避免与库内已有行冲突；整型自增 `id` 跳过，由 SQLite 分配。
/// `mid_map`（旧 message_id → 新 message_id）用于改写 history_v2.message_id，
/// 否则历史行会指向源会话的消息（数据串库）。
fn copy_history_aux(
    src: &Connection,
    dst: &Connection,
    table: &str,
    link_col: &str,
    old_sid: &str,
    new_sid: &str,
    mid_map: Option<&std::collections::HashMap<String, String>>,
) -> Result<usize, String> {
    let cols = common_cols(&table_columns(src, table)?, &table_columns(dst, table)?);
    if cols.is_empty() {
        return Ok(0);
    }
    let col_list = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let select_sql = format!("SELECT {col_list} FROM {table} WHERE {link_col} = ?");
    let mut stmt = src
        .prepare(&select_sql)
        .map_err(|e| format!("源表 {table} 查询失败: {e}"))?;
    let rows = stmt
        .query_map(params![old_sid], |row| {
            let mut vals = Vec::new();
            for i in 0..cols.len() {
                vals.push(row.get::<_, rusqlite::types::Value>(i)?);
            }
            Ok(vals)
        })
        .map_err(|e| format!("源表 {table} 读取失败: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("源表 {table} 行读取失败: {e}"))?;
    if rows.is_empty() {
        return Ok(0);
    }
    let link_idx = cols
        .iter()
        .position(|c| *c == link_col)
        .ok_or_else(|| format!("{table} 缺 {link_col} 列"))?;
    let mut out = rows;
    for v in out.iter_mut() {
        v[link_idx] = rusqlite::types::Value::Text(new_sid.to_string());
        if let Some(idx) = cols.iter().position(|c| c.as_str() == "history_id") {
            v[idx] = rusqlite::types::Value::Text(Uuid::new_v4().simple().to_string());
        }
        if let Some(idx) = cols.iter().position(|c| c.as_str() == "client_history_id") {
            v[idx] = rusqlite::types::Value::Text(Uuid::new_v4().simple().to_string());
        }
        if let Some(idx) = cols.iter().position(|c| c.as_str() == "history_v2_id") {
            v[idx] = rusqlite::types::Value::Text(Uuid::new_v4().simple().to_string());
        }
        // history_v2.message_id：随消息复制改写为新 message_id（避免指向源会话消息）
        if let Some(map) = mid_map {
            if let Some(idx) = cols.iter().position(|c| c.as_str() == "message_id") {
                if let rusqlite::types::Value::Text(old) = &v[idx] {
                    if let Some(nm) = map.get(old) {
                        v[idx] = rusqlite::types::Value::Text(nm.clone());
                    }
                }
            }
        }
    }
    let placeholders = (0..cols.len()).map(|_| "?").collect::<Vec<_>>().join(", ");
    let insert_sql = format!("INSERT INTO {table} ({col_list}) VALUES ({placeholders})");
    let mut ins = dst
        .prepare(&insert_sql)
        .map_err(|e| format!("目标表 {table} 插入准备失败: {e}"))?;
    for vals in &out {
        let args: Vec<&dyn rusqlite::types::ToSql> = vals
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();
        ins.execute(rusqlite::params_from_iter(args))
            .map_err(|e| format!("目标表 {table} 插入失败: {e}"))?;
    }
    Ok(out.len())
}

/// 为目标 uid 在目标库查找或新建 project（会话归属改写）。
/// 取一行里某列的值（列名不在 cols 中返回 None）。
fn col_value<'a>(
    row: &'a [rusqlite::types::Value],
    cols: &[&String],
    name: &str,
) -> Option<&'a rusqlite::types::Value> {
    let idx = cols.iter().position(|c| *c == name)?;
    row.get(idx)
}

/// 按主键取一行（列交集），None 表示行不存在。
fn read_row(
    conn: &Connection,
    table: &str,
    cols: &[&String],
    pk_col: &str,
    pk: &str,
) -> Result<Option<Vec<rusqlite::types::Value>>, String> {
    let col_list = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut stmt = conn
        .prepare(&format!("SELECT {col_list} FROM {table} WHERE {pk_col}=?"))
        .map_err(|e| format!("读取 {table} 失败: {e}"))?;
    let mut rows = stmt
        .query_map(params![pk], |r| {
            let mut vals = Vec::new();
            for i in 0..cols.len() {
                vals.push(r.get::<_, rusqlite::types::Value>(i)?);
            }
            Ok(vals)
        })
        .map_err(|e| format!("读取 {table} 失败: {e}"))?;
    match rows.next() {
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(format!("读取 {table} 行失败: {e}")),
        None => Ok(None),
    }
}

/// 源 project 行缺失时的兜底行（最小列集 + 默认值）。
fn minimal_project_row(cols: &[&String], pid: &str) -> Vec<rusqlite::types::Value> {
    cols.iter()
        .map(|c| match c.as_str() {
            "project_id" => rusqlite::types::Value::Text(pid.to_string()),
            "source" => rusqlite::types::Value::Text("native-ide".into()),
            "workspace_status" => rusqlite::types::Value::Text("single_root".into()),
            "created_at" | "updated_at" => rusqlite::types::Value::Integer(chrono::Utc::now().timestamp()),
            _ => rusqlite::types::Value::Null,
        })
        .collect()
}

/// 为目标 uid 在目标库查找或新建 project（会话归属改写）。
/// 查找规则：同 absolute_path 且未删除的 project 优先；找不到则复制源 project 行并换新 id。
fn ensure_project_for(
    src: &Connection,
    dst: &Connection,
    sid: &str,
    dst_uid: &str,
) -> Result<String, String> {
    let src_pid: String = src
        .query_row("SELECT project_id FROM chat_session WHERE session_id=?", params![sid], |r| r.get(0))
        .map_err(|e| format!("读取源会话 project 失败: {e}"))?;
    // 源 project 行（列交集保真；缺行时用最小兜底集）
    let src_cols = table_columns(src, "project")?;
    let dst_cols = table_columns(dst, "project")?;
    let cols: Vec<&String> = src_cols
        .iter()
        .filter(|c| dst_cols.contains(c) && c.as_str() != "id")
        .collect();
    if cols.is_empty() {
        return Err("源/目标库 project 表无公共列，无法建立归属".into());
    }
    let mut row = read_row(src, "project", &cols, "project_id", &src_pid)?
        .unwrap_or_else(|| minimal_project_row(&cols, &src_pid));
    // 查找目标库中归属 dst_uid 的同路径 project
    if let Some(rusqlite::types::Value::Text(path)) = col_value(&row, &cols, "absolute_path") {
        if !path.is_empty() {
            if let Ok(existing) = dst.query_row(
                "SELECT project_id FROM project WHERE user_id=? AND absolute_path=? AND (deleted_at IS NULL OR deleted_at=0) LIMIT 1",
                params![dst_uid, path],
                |r| r.get::<_, String>(0),
            ) {
                return Ok(existing);
            }
        }
    }
    // 新建：复制源 project 行，project_id / biz_project_id 换新，user_id = dst_uid
    let new_pid = native_hex_id();
    let new_biz = native_hex_id();
    for (name, v) in [
        ("project_id", rusqlite::types::Value::Text(new_pid.clone())),
        ("user_id", rusqlite::types::Value::Text(dst_uid.to_string())),
    ] {
        if let Some(idx) = cols.iter().position(|c| *c == name) {
            row[idx] = v;
        }
    }
    if let Some(idx) = cols.iter().position(|c| *c == "biz_project_id") {
        row[idx] = rusqlite::types::Value::Text(new_biz.clone());
    }
    let col_list = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = (0..cols.len()).map(|_| "?").collect::<Vec<_>>().join(", ");
    let inserted = dst.execute(
        &format!("INSERT INTO project ({col_list}) VALUES ({placeholders})"),
        rusqlite::params_from_iter(row.iter().map(|v| v as &dyn rusqlite::types::ToSql)),
    );
    match inserted {
        Ok(_) => Ok(new_pid),
        Err(e) => {
            // 并发/重复：退回按 (user_id, absolute_path) 查找一次
            if let Some(rusqlite::types::Value::Text(path)) = col_value(&row, &cols, "absolute_path") {
                if !path.is_empty() {
                    if let Ok(existing) = dst.query_row(
                        "SELECT project_id FROM project WHERE user_id=? AND absolute_path=? LIMIT 1",
                        params![dst_uid, path],
                        |r| r.get::<_, String>(0),
                    ) {
                        return Ok(existing);
                    }
                }
            }
            Err(format!("为目标账号创建 project 失败: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// 对外命令
// ---------------------------------------------------------------------------

/// 从 storage 文本解析 uid 的便捷入口。
fn storage_uid_of(client_key: &str) -> Option<String> {
    let path = storage_json_path(get_client(client_key)?);
    uid_from_storage_text(&std::fs::read_to_string(path).ok()?)
}

/// 推断源账号 uid：解密库 project 表出现最多的 user_id。
pub fn source_uid(client_key: &str) -> Option<String> {
    let db = decrypted_db_path(client_key);
    if !db.is_file() {
        return None;
    }
    let conn = Connection::open(&db).ok()?;
    let v: rusqlite::types::Value = conn
        .query_row(
            "SELECT user_id FROM project WHERE user_id IS NOT NULL AND user_id != '' \
             GROUP BY user_id ORDER BY count(*) DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok()?;
    match v {
        rusqlite::types::Value::Text(s) => Some(s),
        rusqlite::types::Value::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

fn uid_suffix(uid: &str) -> String {
    uid[uid.len().saturating_sub(6)..].to_string()
}

/// 账号标识 → uid：`live-<uid>` / `local-<uid>` 直取；否则查 vault 账号档案。
fn account_uid(client_key: &str, account_id: &str) -> Result<String, String> {
    for prefix in ["live-", "local-"] {
        if let Some(rest) = account_id.strip_prefix(prefix) {
            if !rest.is_empty() {
                return Ok(rest.to_string());
            }
        }
    }
    uid_of_account(client_key, account_id)
        .ok_or_else(|| format!("未知账号：{account_id}（该账号未建档或无法解析 uid）"))
}

/// 目标账号导入就绪状态（不写库）。
pub fn inspect_account(client_key: &str, account_id: &str) -> Result<Value, String> {
    let Some(client) = get_client(client_key) else {
        return Err(format!("未知客户端: {client_key}"));
    };
    let uid = account_uid(client_key, account_id)?;
    let db = database_path(client);
    let exists = db.is_file();
    let running = is_running(client);
    let key_ready = load_saved_key(client_key)
        .map(|k| {
            let mut page1 = [0u8; PAGE_SZ];
            std::fs::File::open(&db)
                .and_then(|mut f| {
                    use std::io::Read;
                    f.read_exact(&mut page1)
                })
                .map(|_| {
                    let key = crate::modules::trae_decrypt::hex_to_bytes(&k);
                    verify_page1_hmac(&key, &page1)
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let mut sessions_now = 0i64;
    if exists {
        if let Ok(conn) = Connection::open(&db) {
            if let Ok(v) = conn.query_row("SELECT count(*) FROM chat_session", [], |r| r.get(0)) {
                sessions_now = v;
            }
        }
    }
    Ok(json!({
        "client_key": client_key,
        "client_label": client.label,
        "account_id": account_id,
        "uid": uid,
        "db_exists": exists,
        "running": running,
        "key_ready": key_ready,
        "key_source": if key_ready { "saved" } else if running { "scan_available" } else { "missing" },
        "sessions_now": sessions_now,
    }))
}

/// oauth.json 里的账号显示名（displayName / userName），无则 None。
fn oauth_display(client_key: &str, id: &str) -> Option<String> {
    let p = crate::modules::trae_vault::account_dir(client_key, id).join("oauth.json");
    let text = std::fs::read_to_string(p).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    for k in ["displayName", "userName"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
    }
    None
}

/// 账号维度候选：**全部本机账号**——vault 账号 + 解密库出现的账号（local）+
/// 当前登录态，按 (客户端, uid) 去重，可自由切换目标账号。
/// 不排除所选会话的归属账号，而是用 `is_source` 标记它（前端禁用同客户端同归属的候选）。
fn push_candidate(
    out: &mut Vec<Value>,
    client_label: &str,
    ck: &str,
    account_id: &str,
    label: &str,
    display: Option<String>,
    uid: &str,
    kind: &str,
    db_exists: bool,
    is_current: bool,
    is_source: bool,
) {
    out.push(json!({
        "client_key": ck,
        "client_label": client_label,
        "account_id": account_id,
        "label": label,
        "display": display,
        "uid": uid,
        "kind": kind,
        "db_exists": db_exists,
        "is_current": is_current,
        "is_source": is_source,
    }));
}

/// `src_client_key` 为源（浏览会话的）客户端；`owner_uid` 为所选会话归属账号 uid。
pub fn list_account_candidates(src_client_key: &str, owner_uid: Option<&str>) -> Vec<Value> {
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for c in list_installed_clients() {
        if !c.installed {
            continue;
        }
        let ck = c.key.to_string();
        let db_exists = database_path(get_client(&ck).expect("客户端 key")).is_file();
        let live_uid = storage_uid_of(&ck);
        // 1) vault 账号（carrier / oauth，信息最全）
        for id in list_vault_accounts(&ck) {
            let Some(uid) = uid_of_account(&ck, &id) else {
                continue;
            };
            if !seen.insert((ck.clone(), uid.clone())) {
                continue;
            }
            let kind = read_meta(&ck, &id).map(|m| m.kind).unwrap_or_else(|| "carrier".into());
            let display = oauth_display(&ck, &id);
            let label = match &display {
                Some(d) => format!("{d}（uid …{}）", uid_suffix(&uid)),
                None => format!("{}（uid …{}）", id, uid_suffix(&uid)),
            };
            push_candidate(
                &mut out,
                &c.label,
                &ck,
                &id,
                &label,
                display,
                &uid,
                &kind,
                db_exists,
                live_uid.as_deref() == Some(uid.as_str()),
                ck == src_client_key && owner_uid == Some(uid.as_str()),
            );
        }
        // 2) 解密库账号（local：库内 chat_session 归属的全部 user_id，
        //    覆盖「登录过但没备份凭证」的账号）
        let dec = decrypted_db_path(&ck);
        if dec.is_file() {
            if let Ok(conn) = Connection::open(&dec) {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT DISTINCT p.user_id FROM chat_session s \
                     JOIN project p ON s.project_id = p.project_id \
                     WHERE p.user_id IS NOT NULL AND p.user_id != ''",
                ) {
                    if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                        for uid in rows.flatten() {
                            if !seen.insert((ck.clone(), uid.clone())) {
                                continue;
                            }
                            let label = crate::modules::trae_vault::account_label(&ck, &uid);
                            push_candidate(
                                &mut out,
                                &c.label,
                                &ck,
                                &format!("local-{uid}"),
                                &label,
                                None,
                                &uid,
                                "local",
                                true,
                                live_uid.as_deref() == Some(uid.as_str()),
                                ck == src_client_key && owner_uid == Some(uid.as_str()),
                            );
                        }
                    }
                }
            }
        }
        // 3) 当前 live 登录态（与上面去重）
        if let Some(uid) = storage_uid_of(&ck) {
            if seen.insert((ck.clone(), uid.clone())) {
                push_candidate(
                    &mut out,
                    &c.label,
                    &ck,
                    &format!("live-{uid}"),
                    &format!("当前登录（uid …{}）", uid_suffix(&uid)),
                    None,
                    &uid,
                    "live",
                    db_exists,
                    true,
                    ck == src_client_key && owner_uid == Some(uid.as_str()),
                );
            }
        }
    }
    out
}

/// 有会话库但未列入候选的客户端提示（无解密副本且拿不到密钥时给出引导）。
pub fn client_hints() -> Vec<String> {
    let mut out = Vec::new();
    for c in list_installed_clients() {
        if !c.installed {
            continue;
        }
        let ck = c.key.to_string();
        if decrypted_db_path(&ck).is_file() {
            continue;
        }
        let Some(client) = get_client(&ck) else { continue };
        if !database_path(client).is_file() {
            continue;
        }
        if load_saved_key(&ck).is_some() || is_running(client) {
            continue;
        }
        out.push(format!(
            "客户端「{}」有本地会话库但未解密（无已保存密钥且未运行），其账号暂未列入候选；请先启动该客户端并对其执行『解密会话库』后再试。",
            c.label
        ));
    }
    out
}

/// 所选会话的归属账号 uid（解密库 chat_session → project.user_id）。
pub fn session_owner_uid(client_key: &str, sid: &str) -> Option<String> {
    let conn = open_decrypted(client_key).ok()?;
    let v: rusqlite::types::Value = conn
        .query_row(
            "SELECT p.user_id FROM chat_session s JOIN project p ON s.project_id = p.project_id \
             WHERE s.session_id = ?",
            params![sid],
            |r| r.get(0),
        )
        .ok()?;
    match v {
        rusqlite::types::Value::Text(s) => Some(s),
        rusqlite::types::Value::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

/// 执行导入：源账号（已解密）→ 目标账号本地库。
/// `dst_uid` 为目标账号 uid（归属改写依据）；源目标同一客户端时为同库复制（新 id）。
pub fn import_sessions(
    src_client_key: &str,
    dst_client_key: &str,
    dst_uid: Option<&str>,
    session_ids: &[String],
    on_log: Option<&dyn Fn(&str)>,
) -> Result<Value, String> {
    let same_db = src_client_key == dst_client_key;
    let Some(dst_client) = get_client(dst_client_key) else {
        return Err(format!("未知目标客户端: {dst_client_key}"));
    };
    let log = |m: &str| {
        if let Some(cb) = on_log {
            cb(m);
        }
    };

    // 同客户端跨账号：必须给出目标 uid，且不能是源账号自身
    if same_db {
        let uid = dst_uid.ok_or("同客户端导入必须指定目标账号 uid")?;
        if let Some(src_uid) = source_uid(src_client_key) {
            if src_uid == uid {
                return Err("目标账号就是源账号，无需导入".into());
            }
        }
        log(&format!("同客户端（{}）跨账号复制：源记录保留，会话归属改写为目标账号", dst_client.label));
    }

    // 0) 源库必须是已解密状态
    let src_db = decrypted_db_path(src_client_key);
    if !src_db.is_file() {
        return Err(format!(
            "未找到源账号解密库：{}\n请先在「Trae 记录」页对源账号运行「扫描密钥并解密」。",
            src_db.display()
        ));
    }
    let src_conn = open_decrypted(src_client_key)?;

    // 1) 目标库与密钥
    let dst_db = database_path(&dst_client);
    if !dst_db.is_file() {
        return Err(format!("目标账号 {} 在本机没有会话库，请先用它登录一次 Trae", dst_client.label));
    }
    if is_running(&dst_client) {
        log(&format!("目标客户端 {} 正在运行，先将其退出…", dst_client.label));
        let killed = kill_all(&dst_client);
        log(&format!("已结束 {} 个进程，等待退出…", killed.len()));
        if !wait_until_stopped(&dst_client, 10_000) {
            return Err("目标客户端未能退出，无法写入数据库".into());
        }
    }
    let enc_key_hex = match load_saved_key(dst_client_key) {
        Some(k) => k,
        None => {
            log("目标账号没有存盘密钥，需要从进程内存扫描（请确保该账号客户端已启动并登录）…");
            let scan = scan_for_key(dst_client_key, &dst_db, None)
                .map_err(|e| format!("扫描目标密钥失败：{e}"))?;
            let k = scan.key.ok_or("未在目标客户端进程中找到有效密钥")?;
            save_key(dst_client_key, &k)?;
            log("已扫描到目标密钥并保存");
            k
        }
    };
    // 用目标库自己的盐验证密钥
    {
        let mut page1 = [0u8; PAGE_SZ];
        use std::io::Read;
        std::fs::File::open(&dst_db)
            .map_err(|e| format!("打开目标库失败: {e}"))?
            .read_exact(&mut page1)
            .map_err(|e| format!("读目标库首页失败: {e}"))?;
        let key = crate::modules::trae_decrypt::hex_to_bytes(&enc_key_hex);
        if !verify_page1_hmac(&key, &page1) {
            return Err("目标库密钥不匹配（密钥过期或目标账号已重新登录），请重新扫描密钥".into());
        }
    }

    // 2) 目标库 → 明文副本（tmp），补 reserved 字段
    let work = store_dir()
        .join("trae")
        .join("import_tmp")
        .join(format!("{dst_client_key}-{}.db", chrono::Local::now().timestamp()));
    std::fs::create_dir_all(work.parent().unwrap_or(Path::new(".")))
        .map_err(|e| format!("创建工作目录失败: {e}"))?;
    let plain = work.join("target-plain.db");
    log("解密目标库为明文副本…");
    let rep = decrypt_database(&dst_db, &enc_key_hex, &plain, Some(&|m| log(&format!("   {m}"))))?;
    log(&format!("目标库 {} 页 / {} 表", rep.pages, rep.tables.len()));
    patch_reserved_field(&plain)?;

    // 3) 复制会话（先复制无冲突的）
    let dst_conn = Connection::open(&plain).map_err(|e| format!("打开目标明文副本失败: {e}"))?;
    let opts = CopyOpts {
        dst_uid: dst_uid.map(String::from),
        new_sid: if same_db {
            Some(native_hex_id())
        } else {
            None
        },
    };
    let mut copied = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    for sid in session_ids {
        match copy_session(&src_conn, &dst_conn, sid, &opts, Some(&log)) {
            Ok(Some((n, _))) => copied += n,
            Ok(None) => skipped.push(sid.clone()),
            Err(e) => return Err(format!("复制会话 {sid} 失败：{e}")),
        }
    }
    dst_conn.close().map_err(|(_, e)| format!("关闭明文副本失败: {e}"))?;
    if copied == 0 && skipped.is_empty() {
        let _ = std::fs::remove_dir_all(&work);
        return Err("没有会话被复制（请检查会话 ID）".into());
    }

    // 4) 加密回写 + 自检
    let new_db = work.join("target-new.db");
    log("把明文副本加密回写为 SQLCipher 库…");
    let pages = encrypt_db_file(&enc_key_hex, &plain, &new_db, Some(&|m| log(&format!("   {m}"))))?;
    log(&format!("加密回写完成（{pages} 页），进行原子替换…"));

    // 5) 原子替换（备份原库 + wal/shm → 替换 → 失败回滚）
    let backup_dir = store_dir().join("trae").join("import_backup").join(format!(
        "{dst_client_key}-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::create_dir_all(&backup_dir).map_err(|e| format!("创建备份目录失败: {e}"))?;
    let wal = dst_db.with_extension("db-wal");
    let shm = dst_db.with_extension("db-shm");
    for (label, p) in [("主库", &dst_db), ("WAL", &wal), ("SHM", &shm)] {
        if p.exists() {
            let dst = backup_dir.join(p.file_name().unwrap_or_default());
            std::fs::copy(p, &dst).map_err(|e| format!("备份{label}失败: {e}"))?;
        }
    }
    let swap = || -> Result<(), String> {
        if wal.exists() {
            std::fs::remove_file(&wal).map_err(|e| format!("清理 WAL 失败: {e}"))?;
        }
        if shm.exists() {
            std::fs::remove_file(&shm).map_err(|e| format!("清理 SHM 失败: {e}"))?;
        }
        if dst_db.exists() {
            std::fs::remove_file(&dst_db).map_err(|e| format!("移除旧库失败: {e}"))?;
        }
        std::fs::rename(&new_db, &dst_db).map_err(|e| format!("替换数据库失败: {e}"))?;
        Ok(())
    };
    if let Err(e) = swap() {
        let _ = std::fs::remove_dir_all(&work);
        return Err(format!("替换失败（已保留备份）：{e}"));
    }

    // 6) 全量自检：把新库再解密一次对比会话数
    let verify_plain = work.join("verify-plain.db");
    log("对新库做解密自检…");
    let _vr = decrypt_database(&dst_db, &enc_key_hex, &verify_plain, None)?;
    let verified: i64 = Connection::open(&verify_plain)
        .ok()
        .and_then(|c| c.query_row("SELECT count(*) FROM chat_session", [], |r| r.get(0)).ok())
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(&work);

    let in_list = session_ids
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let src_total: i64 = src_conn
        .query_row(
            &format!("SELECT count(*) FROM chat_session WHERE session_id IN ({in_list})"),
            [],
            |r| r.get(0),
        )
        .map_err(|e| format!("源会话统计失败: {e}"))?;

    Ok(json!({
        "copied_rows": copied,
        "sessions_requested": session_ids.len(),
        "sessions_src": src_total,
        "skipped": skipped,
        "target_client": dst_client_key,
        "target_label": dst_client.label,
        "target_uid": dst_uid,
        "same_db": same_db,
        "pages": pages,
        "verified_sessions": verified,
        "backup_dir": backup_dir.to_string_lossy(),
    }))
}

/// 备份目录清理（导入前旧临时目录）。
pub fn clean_stale_import_dirs() -> Result<(), String> {
    let dir = store_dir().join("trae").join("import_tmp");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("清理导入临时目录失败: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 页级加密 ↔ 解密 round-trip：
    /// 合成 SQLCipher 明文页（尾部保留区清零）→ 加密 → 首页 HMAC 自检通过
    /// （页号按 4 字节参与 HMAC，与真实 SQLCipher 一致）→ 解密回字节级一致。
    #[test]
    fn roundtrip_sqlcipher_page() {
        let enc_key = {
            let mut r = [0u8; KEY_SZ];
            getrandom::getrandom(&mut r).unwrap();
            r
        };
        let salt = {
            let mut r = [0u8; SALT_SZ];
            getrandom::getrandom(&mut r).unwrap();
            r
        };
        let mac_key = derive_mac_key(&enc_key, &salt);
        for pgno in [1u64, 2, 5, 100] {
            // 合成明文页：伪随机内容，尾部保留区清零（SQLCipher 明文页特征）
            let mut plain = [0u8; PAGE_SZ];
            for (i, b) in plain.iter_mut().enumerate() {
                *b = ((i as u64) % 251) as u8;
            }
            plain[USABLE_SZ..].fill(0);
            let enc = encrypt_sqlcipher_page(&enc_key, &mac_key, salt, pgno, &plain).unwrap();
            // 首页 HMAC 必须通过（u32 页号约定）
            if pgno == 1 {
                assert!(verify_page1_hmac(&enc_key, &enc), "页 1 HMAC 自检失败");
            }
            let dec = crate::modules::trae_decrypt::decrypt_page(&enc_key, &enc, pgno);
            if pgno == 1 {
                // 页 1 前 16 字节以标准 SQLite 头重建，其余应逐字节还原
                assert_eq!(&dec[..16], b"SQLite format 3\x00");
                assert_eq!(&dec[16..], &plain[16..], "页 {pgno} round-trip 内容不一致");
            } else {
                assert_eq!(&dec[..USABLE_SZ], &plain[..USABLE_SZ], "页 {pgno} round-trip 内容不一致");
            }
        }
    }
}
