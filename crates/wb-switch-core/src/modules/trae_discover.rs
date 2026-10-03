//! Trae 客户端发现：定位各版本的用户数据目录、可执行文件与进程名（移植自 trae-switch src/discover.js）。
//!
//! 同一台机器可能同时装 Trae CN 与 TRAE SOLO CN，二者账号库相互独立；
//! 登录态只认 `storage.json` 的 `iCubeAuthInfo://*`。

use std::path::{Path, PathBuf};

use serde::Serialize;

/// 客户端定义。
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TraeClient {
    pub key: &'static str,
    pub label: &'static str,
    pub user_data: &'static str,
    pub api_host: &'static str,
    /// 会话/任务类接口的 remote 网关（安装目录可读时以 product.json 为准）。
    pub remote_host: &'static str,
}

pub const CLIENTS: [TraeClient; 4] = [
    TraeClient {
        key: "trae-cn",
        label: "Trae CN（IDE 国内版）",
        user_data: "Trae CN",
        api_host: "https://api.trae.cn",
        remote_host: "https://trae-api-cn.mchost.guru",
    },
    TraeClient {
        key: "solo-cn",
        label: "TRAE SOLO CN",
        user_data: "TRAE SOLO CN",
        api_host: "https://api.trae.cn",
        remote_host: "https://trae-api-cn.mchost.guru",
    },
    TraeClient {
        key: "trae-intl",
        label: "Trae（国际版）",
        user_data: "Trae",
        api_host: "https://api.trae.ai",
        remote_host: "https://api.trae.ai",
    },
    TraeClient {
        key: "solo-intl",
        label: "TRAE SOLO（国际版）",
        user_data: "TRAE SOLO",
        api_host: "https://api.trae.ai",
        remote_host: "https://api.trae.ai",
    },
];

pub fn get_client(key: &str) -> Option<&'static TraeClient> {
    CLIENTS.iter().find(|c| c.key == key)
}

pub fn appdata_dir() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_default().join("AppData").join("Roaming"))
}

pub fn localappdata_dir() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_default().join("AppData").join("Local"))
}

pub fn user_data_dir(client: &TraeClient) -> PathBuf {
    appdata_dir().join(client.user_data)
}

pub fn storage_json_path(client: &TraeClient) -> PathBuf {
    user_data_dir(client).join("User").join("globalStorage").join("storage.json")
}

/// 探测客户端主程序路径；未装返回 None。
pub fn detect_exe(client: &TraeClient) -> Option<PathBuf> {
    let exe_names: [&str; 2] = match client.key {
        "trae-cn" => ["Trae CN.exe", "Trae.exe"],
        "solo-cn" => ["TRAE SOLO CN.exe", "Trae Solo.exe"],
        "trae-intl" => ["Trae.exe", "Trae CN.exe"],
        _ => ["TRAE SOLO.exe", "Trae Solo.exe"],
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    dirs.push(user_data_dir(client));
    dirs.push(localappdata_dir().join("Programs").join(client.user_data));
    dirs.push(localappdata_dir().join(client.user_data));
    for base in [
        std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into()),
        std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".into()),
    ] {
        dirs.push(PathBuf::from(base).join(client.user_data));
    }
    for ch in "CDEFGH".chars() {
        for sub in ["Program Files", "Program Files (x86)"] {
            dirs.push(PathBuf::from(format!("{ch}:\\")).join(sub).join(client.user_data));
        }
    }
    for dir in dirs {
        for name in exe_names {
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
        }
        // 目录里名字含 Trae 的 exe 兜底
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let mut hit: Option<PathBuf> = None;
            let mut count = 0usize;
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if !name.ends_with(".exe") {
                    continue;
                }
                count += 1;
                if name.contains("trae") {
                    hit = Some(e.path());
                }
            }
            if hit.is_some() {
                return hit;
            }
            if count == 1 {
                let _ = count;
                for e in std::fs::read_dir(&dir).ok()?.flatten() {
                    if e.file_name().to_string_lossy().to_lowercase().ends_with(".exe") {
                        return Some(e.path());
                    }
                }
            }
        }
    }
    None
}

/// 进程名（tasklist 过滤用）。
pub fn process_names(client: &TraeClient) -> &'static [&'static str] {
    match client.key {
        "trae-cn" => &["Trae CN", "Trae"],
        "solo-cn" => &["TRAE SOLO CN"],
        "trae-intl" => &["Trae"],
        _ => &["TRAE SOLO"],
    }
}

/// 读取安装目录 product.json 的 remote 网关；失败回落默认值。
pub fn remote_host(client: &TraeClient) -> String {
    if let Some(exe) = detect_exe(client) {
        if let Some(dir) = exe.parent() {
            let pj = dir.join("resources").join("app").join("product.json");
            if let Ok(text) = std::fs::read_to_string(&pj) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(h) = v
                        .get("bootConfig")
                        .and_then(|b| b.get("remote"))
                        .and_then(|r| r.get("trae"))
                        .and_then(|t| t.get("normal"))
                        .and_then(|n| n.as_str())
                    {
                        if h.starts_with("https://") || h.starts_with("http://") {
                            return h.trim_end_matches('/').to_string();
                        }
                    }
                }
            }
        }
    }
    client.remote_host.to_string()
}

/// 该客户端当前是否确实处于登录态（两把凭据键都在且非空）。
pub fn has_login_state(client: &TraeClient) -> bool {
    let Ok(text) = std::fs::read_to_string(storage_json_path(client)) else {
        return false;
    };
    let Ok(j) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let auth = j.get("iCubeAuthInfo://icube.cloudide").and_then(|v| v.as_str());
    let tag = j.get("iCubeAuthInfo://usertag").and_then(|v| v.as_str());
    auth.map(|a| !a.trim().is_empty()).unwrap_or(false)
        && tag.map(|t| !t.trim().is_empty()).unwrap_or(false)
}

/// 已安装（有数据目录）的客户端列表。
#[derive(Serialize)]
pub struct InstalledClient {
    pub key: &'static str,
    pub label: &'static str,
    pub user_data_dir: String,
    pub installed: bool,
    pub exe: Option<String>,
    pub has_login: bool,
}

pub fn list_installed_clients() -> Vec<InstalledClient> {
    CLIENTS
        .iter()
        .map(|c| {
            let dir = user_data_dir(c);
            let installed = dir.exists();
            InstalledClient {
                key: c.key,
                label: c.label,
                user_data_dir: dir.to_string_lossy().into_owned(),
                installed,
                exe: detect_exe(c).map(|p| p.to_string_lossy().into_owned()),
                has_login: installed && has_login_state(c),
            }
        })
        .collect()
}

/// 数据库路径：`%APPDATA%\<userData>\ModularData\ai-agent\database.db`。
pub fn database_path(client: &TraeClient) -> PathBuf {
    user_data_dir(client)
        .join("ModularData")
        .join("ai-agent")
        .join("database.db")
}

/// snapshot 会话目录根。
pub fn snapshot_root(client: &TraeClient) -> PathBuf {
    user_data_dir(client).join("ModularData").join("ai-agent").join("snapshot")
}

/// 全局附加目录（worktrees / mcps 按会话 ID 命名）。
pub fn extra_roots() -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_default().join(".trae-cn");
    vec![home.join("worktrees"), home.join("mcps")]
}

/// 判断路径是否是某客户端的数据目录（供校验）。
pub fn is_client_root(client: &TraeClient, dir: &Path) -> bool {
    dir == user_data_dir(client)
}
