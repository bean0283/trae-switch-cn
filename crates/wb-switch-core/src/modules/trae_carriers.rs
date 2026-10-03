//! 载体（登录态载体文件）处理（移植自 trae-switch src/carriers.js）。
//!
//! 载体 = 一个账号在本机留下的全部登录态文件：`User/globalStorage/storage.json`
//! （主凭据 `iCubeAuthInfo://*`）+ 各处 leveldb 目录。冷切换时必须整组一起换，
//! 只换 storage.json 会出现「半新半旧」的登录态。本模块只做字节级拷贝与哈希比对，不解密。

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// 扫描载体时跳过的目录名（体积大且与账号身份无关）。
pub const EXCLUDE_DIRS: &[&str] = &[
    "Cache",
    "CachedData",
    "CachedConfigurations",
    "CachedProfilesData",
    "CachedExtensionVSIXs",
    "Code Cache",
    "GPUCache",
    "Crashpad",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "ShaderCache",
    "Dictionaries",
    "blob_storage",
    "Service Worker",
    "Shared Dictionary",
    "logs",
    "Backups",
    "ModularData",
    "node_modules",
];

/// 运行痕迹文件：每次客户端启动都会改写，与账号身份无关，识别时不计入。
const RUNTIME_STATE: &[&str] = &[
    "local storage/config.db",
    "network/network persistent state",
    "user/globalstorage/storage.json",
];

/// 匹配 `local storage/leveldb` 这一级（含其下文件、以及 Partitions/* 里的同名目录）。
const GLOBAL_STATE_MARKER: &str = "local storage/leveldb";

/// 规范化相对路径：统一正斜杠、小写。
pub fn norm_rel(rel: &str) -> String {
    rel.replace('\\', "/")
}

fn norm_lower(rel: &str) -> String {
    norm_rel(rel).to_lowercase()
}

/// 全局状态条目（分区本地状态，不是登录态，切换时绝不能替换）。
pub fn is_global_state_entry(rel: &str) -> bool {
    let t = norm_lower(rel);
    t.contains(GLOBAL_STATE_MARKER)
}

pub fn is_runtime_state_file(rel: &str) -> bool {
    let t = norm_lower(rel);
    RUNTIME_STATE.iter().any(|r| t == *r)
}

/// 去掉全局状态条目并去重（保持原顺序）。
pub fn sanitize_entries(entries: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for e in entries {
        let r = norm_rel(e);
        if r.is_empty() || is_global_state_entry(&r) || seen.contains(&r) {
            continue;
        }
        seen.insert(r.clone());
        out.push(r);
    }
    out
}

pub fn hash_file(p: &Path) -> Option<String> {
    let data = std::fs::read(p).ok()?;
    use sha2::Digest;
    let h = sha2::Sha256::digest(&data);
    Some(hex_encode(&h))
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// 自动探测某客户端用户数据目录下的载体条目（相对路径列表）。
/// 策略：storage.json + 深度 ≤5 的所有 leveldb 目录，上限 16 条。
pub fn detect_carrier_entries(root_dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    if !root_dir.exists() {
        return found;
    }
    let storage = root_dir.join("User").join("globalStorage").join("storage.json");
    if storage.is_file() {
        found.push("User/globalStorage/storage.json".into());
    }

    fn walk(root: &Path, rel: &str, depth: usize, found: &mut Vec<String>) {
        if depth > 5 || found.len() >= 16 {
            return;
        }
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()))
        };
        let Ok(children) = std::fs::read_dir(&dir) else {
            return;
        };
        for child in children.flatten() {
            let Ok(meta) = child.metadata() else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let name = child.file_name().to_string_lossy().into_owned();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if name.eq_ignore_ascii_case("leveldb") {
                if !is_global_state_entry(&child_rel) {
                    found.push(child_rel);
                }
            } else if !EXCLUDE_DIRS.iter().any(|d| d.eq_ignore_ascii_case(&name)) {
                walk(root, &child_rel, depth + 1, found);
            }
        }
    }
    walk(root_dir, "", 0, &mut found);
    found
}

/// 把载体条目展开成具体文件相对路径（目录则递归其中全部文件）。
pub fn expand_entries(root_dir: &Path, entries: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for rel in entries {
        let p = root_dir.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            fn walk_dir(root: &Path, rel: &str, out: &mut Vec<String>) {
                let dir = root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
                let Ok(children) = std::fs::read_dir(&dir) else {
                    return;
                };
                for child in children.flatten() {
                    let Ok(meta) = child.metadata() else {
                        continue;
                    };
                    let name = child.file_name().to_string_lossy().into_owned();
                    let child_rel = if rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{rel}/{name}")
                    };
                    if meta.is_dir() {
                        walk_dir(root, &child_rel, out);
                    } else {
                        out.push(child_rel);
                    }
                }
            }
            walk_dir(root_dir, rel, &mut out);
        } else {
            out.push(norm_rel(rel));
        }
    }
    out
}

/// 复制 `src_root/rel → dst_root/rel`；目录条目整树覆盖（先删后写，避免 leveldb 残留孤儿文件）。
pub fn overwrite_entry(src_root: &Path, dst_root: &Path, rel: &str) {
    let src = src_root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
    let dst = dst_root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
    let Ok(meta) = std::fs::metadata(&src) else {
        return; // 源侧不存在，跳过
    };
    if meta.is_dir() {
        let _ = std::fs::remove_dir_all(&dst);
        if std::fs::create_dir_all(&dst).is_err() {
            return;
        }
        fn copy_tree(src: &Path, dst: &Path) {
            let Ok(children) = std::fs::read_dir(src) else {
                return;
            };
            for child in children.flatten() {
                let Ok(meta) = child.metadata() else {
                    continue;
                };
                let d = dst.join(child.file_name());
                if meta.is_dir() {
                    let _ = std::fs::create_dir_all(&d);
                    copy_tree(&child.path(), &d);
                } else {
                    let _ = std::fs::create_dir_all(d.parent().unwrap_or(dst));
                    let _ = std::fs::copy(child.path(), d);
                }
            }
        }
        copy_tree(&src, &dst);
    } else {
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(src, dst);
    }
}

/// 全树哈希（用于「重新探测载体」的差异比对）。
pub fn hash_tree(root_dir: &Path, max_files: usize) -> HashMap<String, String> {
    let mut map = HashMap::new();
    fn walk(root: &Path, rel: &str, max_files: usize, map: &mut HashMap<String, String>) {
        if map.len() >= max_files {
            return;
        }
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()))
        };
        let Ok(children) = std::fs::read_dir(&dir) else {
            return;
        };
        for child in children.flatten() {
            if map.len() >= max_files {
                return;
            }
            let Ok(meta) = child.metadata() else {
                continue;
            };
            let name = child.file_name().to_string_lossy().into_owned();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if meta.is_dir() {
                if EXCLUDE_DIRS.iter().any(|d| d.eq_ignore_ascii_case(&name)) {
                    continue;
                }
                walk(root, &child_rel, max_files, map);
            } else {
                if let Some(h) = hash_file(&child.path()) {
                    map.insert(child_rel, h);
                }
            }
        }
    }
    walk(root_dir, "", max_files, &mut map);
    map
}

/// 载体文件记录（建档时逐文件哈希）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CarrierFile {
    pub rel: String,
    pub len: i64,
    pub sha256: String,
}
