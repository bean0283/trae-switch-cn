//! 账号库（vault）：按账号把「载体」原样字节备份 / 还原，并做哈希校验、归属识别、导入导出
//! （移植自 trae-switch src/vault.js）。
//!
//! 只做字节拷贝，不解密、不改动内容；导入/导出走自包含 JSON（文件内容 base64 内联）。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::modules::config::store_dir;
use crate::modules::trae_carriers::{
    expand_entries, hash_file, overwrite_entry, sanitize_entries, CarrierFile,
};
use crate::modules::trae_discover::TraeClient;
use crate::modules::trae_km::{decrypt_km_json, is_km_value};

pub const KEY_AUTH: &str = "iCubeAuthInfo://icube.cloudide";
pub const REL_STORAGE: &str = "User/globalStorage/storage.json";

/// 把名字清洗成安全目录名。
pub fn sanitize_name(name: &str) -> String {
    let t: String = name
        .chars()
        .map(|c| if "\\/:*?\"<>|\r\n\t".contains(c) { '_' } else { c })
        .collect();
    let t = t.trim().to_string();
    if t.is_empty() {
        "account".into()
    } else {
        t
    }
}

/// vault 根目录：`<工具目录>/trae/vault/<clientKey>/<accountId>/`。
pub fn vault_root() -> PathBuf {
    store_dir().join("trae").join("vault")
}

pub fn account_dir(client_key: &str, id: &str) -> PathBuf {
    vault_root().join(client_key).join(sanitize_name(id))
}

pub fn meta_path(client_key: &str, id: &str) -> PathBuf {
    account_dir(client_key, id).join("meta.json")
}

/// 从 storage.json 文本里解出账号 uid（未登录 / 非 Km 条目 → None）。
pub fn uid_from_storage_text(text: &str) -> Option<String> {
    let root = serde_json::from_str::<Value>(text).ok()?;
    let raw = root.get(KEY_AUTH)?;
    let raw_str = raw.as_str()?;
    if !is_km_value(raw_str) {
        return None;
    }
    let auth = decrypt_km_json(raw_str)?;
    match auth.get("userId") {
        Some(v) => v.as_i64().map(|i| i.to_string()).or_else(|| v.as_str().map(String::from)),
        None => None,
    }
}

fn uid_from_storage_file(p: &Path) -> Option<String> {
    uid_from_storage_text(&std::fs::read_to_string(p).ok()?)
}

/// 档案里该账号的 uid：优先 storage.json（客户端真正认的），其次 oauth.json。
pub fn uid_of_account(client_key: &str, id: &str) -> Option<String> {
    let dir = account_dir(client_key, id);
    if let Some(uid) = uid_from_storage_file(&dir.join(REL_STORAGE)) {
        return Some(uid);
    }
    let oauth = dir.join("oauth.json");
    if let Ok(text) = std::fs::read_to_string(&oauth) {
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if let Some(uid) = v.get("uid") {
                if let Some(s) = uid.as_str() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// 列出某客户端下已有的账号目录。
pub fn list_vault_accounts(client_key: &str) -> Vec<String> {
    let dir = vault_root().join(client_key);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.metadata().map(|m| m.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

fn uid_suffix(uid: &str) -> String {
    uid[uid.len().saturating_sub(6)..].to_string()
}

/// 账号显示名：优先 oauth.json 的 displayName / userName，
/// 其次 vault 账号目录名，兜底仅 uid 尾号。找不到档案时同样兜底 uid 尾号。
pub fn account_label(client_key: &str, uid: &str) -> String {
    for id in list_vault_accounts(client_key) {
        if uid_of_account(client_key, &id).as_deref() == Some(uid) {
            let p = account_dir(client_key, &id).join("oauth.json");
            if let Ok(text) = std::fs::read_to_string(&p) {
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    for k in ["displayName", "userName"] {
                        if let Some(s) = v
                            .get(k)
                            .and_then(|x| x.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            return format!("{s}（uid …{}）", uid_suffix(uid));
                        }
                    }
                    return format!("{id}（uid …{}）", uid_suffix(uid));
                }
            }
            return format!("{id}（uid …{}）", uid_suffix(uid));
        }
    }
    format!("uid …{}", uid_suffix(uid))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub id: String,
    pub client: String,
    /// 账号类型：`carrier`（客户端登录态载体，可切换）/ `oauth`（网页登录凭证，仅可查询）。
    /// 历史账号无此字段，反序列化按 carrier 处理。
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub root_dir: String,
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default)]
    pub files: Vec<CarrierFile>,
    #[serde(default)]
    pub file_count: usize,
    #[serde(default)]
    pub total_bytes: u64,
    pub created_at: String,
    /// 最近一次切换成功时间（RFC3339）。
    #[serde(default)]
    pub last_used_at: Option<String>,
    /// 最近一次切换成功时客户端确认的账号 uid。
    #[serde(default)]
    pub verified_uid: Option<String>,
}

/// 切换成功后更新账号元数据（last_used_at / verified_uid）。
pub fn mark_used(client_key: &str, id: &str, verified_uid: Option<String>) {
    let Some(mut meta) = read_meta(client_key, id) else {
        return;
    };
    meta.last_used_at = Some(chrono::Local::now().to_rfc3339());
    meta.verified_uid = verified_uid;
    let path = meta_path(client_key, id);
    let _ = std::fs::write(path, serde_json::to_string_pretty(&meta).unwrap_or_default());
}

pub fn read_meta(client_key: &str, id: &str) -> Option<VaultMeta> {
    let text = std::fs::read_to_string(meta_path(client_key, id)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 建档：把 rootDir 下 entries 指向的载体复制进 vault。
pub fn backup(client_key: &str, id: &str, root_dir: &Path, entries: &[String]) -> Result<VaultMeta, String> {
    let dst_root = account_dir(client_key, id);
    std::fs::create_dir_all(&dst_root).map_err(|e| format!("创建账号目录失败: {e}"))?;
    let list = sanitize_entries(entries);
    for rel in &list {
        overwrite_entry(root_dir, &dst_root, rel);
    }
    let mut files = Vec::new();
    for rel in expand_entries(root_dir, &list) {
        let p = dst_root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        if let Ok(meta) = std::fs::metadata(&p) {
            files.push(CarrierFile {
                rel: rel.clone(),
                len: meta.len() as i64,
                sha256: hash_file(&p).unwrap_or_default(),
            });
        }
    }
    let total: u64 = files.iter().map(|f| f.len.max(0) as u64).sum();
    let meta = VaultMeta {
        id: id.to_string(),
        client: client_key.to_string(),
        kind: "carrier".into(),
        root_dir: root_dir.to_string_lossy().into_owned(),
        entries: list,
        file_count: files.len(),
        files,
        total_bytes: total,
        created_at: chrono::Local::now().to_rfc3339(),
        last_used_at: None,
        verified_uid: None,
    };
    let path = meta_path(client_key, id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?)
        .map_err(|e| format!("写 meta 失败: {e}"))?;
    Ok(meta)
}

/// 还原：把 vault 里的载体写回 rootDir。
pub fn restore(client_key: &str, id: &str, root_dir: &Path, entries: &[String]) -> Result<usize, String> {
    let src_root = account_dir(client_key, id);
    if !src_root.exists() {
        return Err(format!("账号 {id} 未建档"));
    }
    let meta_entries = read_meta(client_key, id).map(|m| m.entries).unwrap_or_default();
    let list = sanitize_entries(if !entries.is_empty() { entries } else { &meta_entries });
    for rel in &list {
        overwrite_entry(&src_root, root_dir, rel);
    }
    Ok(list.len())
}

/// 校验：vault 与 live 逐文件哈希一致。
pub fn verify(client_key: &str, id: &str, root_dir: &Path) -> Result<Value, String> {
    let Some(meta) = read_meta(client_key, id) else {
        return Err("未建档".into());
    };
    let mut checked = 0usize;
    let mut mismatched = Vec::new();
    for f in &meta.files {
        let v = account_dir(client_key, id).join(f.rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        let l = root_dir.join(f.rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        if !v.is_file() || !l.is_file() {
            continue;
        }
        checked += 1;
        if hash_file(&v) != hash_file(&l) {
            mismatched.push(f.rel.clone());
        }
    }
    Ok(json!({
        "ok": mismatched.is_empty(),
        "checked": checked,
        "mismatched": mismatched.iter().take(20).collect::<Vec<_>>(),
    }))
}

/// 归属识别：当前 live 更像哪个账号。首选 uid 比对（解密 storage.json），
/// uid 解不出时退回哈希相似度。
pub fn identify(client_key: &str, root_dir: &Path) -> Option<Value> {
    let ids = list_vault_accounts(client_key);
    if ids.is_empty() {
        return None;
    }
    let live_uid = uid_from_storage_file(&root_dir.join(REL_STORAGE));
    if let Some(live_uid) = live_uid {
        let mut rows: Vec<Value> = ids
            .iter()
            .filter_map(|id| {
                let uid = uid_of_account(client_key, id)?;
                let hit = uid == live_uid;
                Some(json!({ "id": id, "score": if hit { 1 } else { 0 }, "hit": hit as i32, "total": 1, "uid": uid }))
            })
            .collect();
        rows.sort_by(|a, b| b["score"].as_i64().unwrap_or(0).cmp(&a["score"].as_i64().unwrap_or(0)));
        if !rows.is_empty() {
            return Some(json!({ "best": rows[0], "all": rows, "by": "uid", "live_uid": live_uid }));
        }
    }
    // 兜底：哈希相似度（简化为按判别文件命中率）
    let usable: Vec<VaultMeta> = ids.iter().filter_map(|id| read_meta(client_key, id)).collect();
    if usable.is_empty() {
        return None;
    }
    let discriminant = build_discriminant(&usable);
    let mut scored: Vec<(String, f64, usize, usize)> = Vec::new();
    for m in &usable {
        let mut total = 0usize;
        let mut hit = 0usize;
        for f in &m.files {
            let rel = f.rel.clone();
            if is_runtime_state_file(&rel) || (discriminant.is_some() && !discriminant.as_ref().unwrap().contains(&rel)) {
                continue;
            }
            total += 1;
            let live = root_dir.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
            if hash_file(&live).as_deref() == Some(f.sha256.as_str()) {
                hit += 1;
            }
        }
        if total > 0 {
            scored.push((m.id.clone(), hit as f64 / total as f64, hit, total));
        }
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    if scored.is_empty() {
        return None;
    }
    let (id, score, hit, total) = &scored[0];
    Some(json!({
        "best": { "id": id, "score": score, "hit": hit, "total": total },
        "all": scored.iter().map(|(id, score, hit, total)| json!({ "id": id, "score": score, "hit": hit, "total": total })).collect::<Vec<_>>(),
        "by": "hash",
    }))
}

fn is_runtime_state_file(rel: &str) -> bool {
    let t = rel.to_lowercase();
    matches!(t.as_str(), "local storage/config.db" | "network/network persistent state" | "user/globalstorage/storage.json")
}

/// 判别文件集合：跨账号哈希互不相同，或仅部分账号拥有。
fn build_discriminant(metas: &[VaultMeta]) -> Option<HashSetString> {
    let mut by_rel: HashMap<String, (HashSet<String>, usize)> = HashMap::new();
    let n = metas.len();
    for m in metas {
        let mut seen = HashSet::new();
        for f in &m.files {
            let rel = f.rel.clone();
            if is_runtime_state_file(&rel) || seen.contains(&rel) {
                continue;
            }
            seen.insert(rel.clone());
            let e = by_rel.entry(rel).or_insert_with(|| (HashSet::new(), 0));
            e.0.insert(f.sha256.clone());
        }
    }
    for m in metas {
        let mut seen = HashSet::new();
        for f in &m.files {
            let rel = f.rel.clone();
            if is_runtime_state_file(&rel) || seen.contains(&rel) {
                continue;
            }
            seen.insert(rel.clone());
            if let Some(e) = by_rel.get_mut(&rel) {
                e.1 += 1;
            }
        }
    }
    let mut set = HashSet::new();
    for (rel, (shas, owners)) in by_rel {
        if shas.len() > 1 || owners < n {
            set.insert(rel);
        }
    }
    if set.is_empty() {
        None
    } else {
        Some(HashSetString(set))
    }
}

/// 判别文件集合的包装（内部 HashSet<String>）。
pub struct HashSetString(pub HashSet<String>);

impl HashSetString {
    pub fn contains(&self, s: &str) -> bool {
        self.0.contains(s)
    }
}

/// 从存储文本里取 uid 的便捷入口（供外部调用）。
pub fn uid_of_live_storage(text: &str) -> Option<String> {
    uid_from_storage_text(text)
}

pub fn remove_account(client_key: &str, id: &str) -> Result<(), String> {
    let dir = account_dir(client_key, id);
    if !dir.exists() {
        return Err("账号不存在".into());
    }
    std::fs::remove_dir_all(&dir).map_err(|e| format!("删除账号失败: {e}"))
}

pub fn rename_account(client_key: &str, from_id: &str, to_id: &str) -> Result<String, String> {
    let from = account_dir(client_key, from_id);
    let to = account_dir(client_key, to_id);
    if !from.exists() {
        return Err("账号不存在".into());
    }
    if to.exists() {
        return Err(format!("目标名 {to_id} 已存在"));
    }
    std::fs::rename(&from, &to).map_err(|e| format!("重命名失败: {e}"))?;
    if let Some(mut meta) = read_meta(client_key, to_id) {
        meta.id = to_id.to_string();
        let path = meta_path(client_key, to_id);
        std::fs::write(path, serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?)
            .map_err(|e| format!("更新 meta 失败: {e}"))?;
    }
    Ok(to_id.to_string())
}

const EXPORT_FORMAT: &str = "trae-switch-vault";
const EXPORT_VERSION: i64 = 1;

/// 导出为单个 JSON 文本（文件内容 base64 内联）。
pub fn export_account(client_key: &str, id: &str) -> Result<Value, String> {
    let dir = account_dir(client_key, id);
    let meta = read_meta(client_key, id).ok_or("账号未建档，无法导出")?;
    let mut files = Vec::new();
    for f in &meta.files {
        let p = dir.join(f.rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        let Ok(data) = std::fs::read(&p) else {
            continue;
        };
        files.push(json!({ "rel": f.rel, "len": f.len, "sha256": f.sha256, "b64": STANDARD.encode(data) }));
    }
    Ok(json!({
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported_at": chrono::Local::now().to_rfc3339(),
        "client": client_key,
        "id": id,
        "entries": sanitize_entries(&meta.entries),
        "files": files,
    }))
}

/// 从导出 JSON 恢复到 vault；冲突时自动加后缀。返回新账号 id。
pub fn import_account(client_key: &str, payload: &Value, prefer_name: Option<&str>) -> Result<(String, usize), String> {
    if payload.get("format").and_then(|v| v.as_str()) != Some(EXPORT_FORMAT) {
        return Err("不是 trae-switch 导出的账号文件".into());
    }
    let base = sanitize_name(prefer_name.unwrap_or(payload.get("id").and_then(|v| v.as_str()).unwrap_or("imported")));
    let mut id = base.clone();
    let mut n = 1usize;
    while account_dir(client_key, &id).exists() {
        id = format!("{base}_{}", n + 1);
        n += 1;
    }
    let dir = account_dir(client_key, &id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建账号目录失败: {e}"))?;
    let mut files = Vec::new();
    for f in payload.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let Some(rel) = f.get("rel").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(b64) = f.get("b64").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(data) = STANDARD.decode(b64) else {
            continue;
        };
        let p = dir.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&p, data).is_err() {
            continue;
        }
        files.push(CarrierFile {
            rel: rel.to_string(),
            len: f.get("len").and_then(|v| v.as_i64()).unwrap_or(0),
            sha256: f.get("sha256").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        });
    }
    let entries = payload.get("entries").and_then(|v| v.as_array()).map(|a| {
        a.iter().filter_map(|v| v.as_str()).map(String::from).collect::<Vec<_>>()
    }).unwrap_or_default();
    let file_count = files.len();
    let meta = VaultMeta {
        id: id.clone(),
        client: client_key.to_string(),
        kind: "carrier".into(),
        root_dir: String::new(),
        entries: sanitize_entries(&entries),
        file_count,
        files,
        total_bytes: 0,
        created_at: chrono::Local::now().to_rfc3339(),
        last_used_at: None,
        verified_uid: None,
    };
    let path = meta_path(client_key, &id);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?)
        .map_err(|e| format!("写 meta 失败: {e}"))?;
    Ok((id, file_count))
}

/// 便捷：uid 字段取值。
pub fn value_uid(v: &Value) -> Option<String> {
    v.as_i64().map(|i| i.to_string()).or_else(|| v.as_str().map(String::from))
}

#[allow(unused)]
fn unused_trae_client_guard(_c: &TraeClient) {}
