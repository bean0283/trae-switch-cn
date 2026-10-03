//! Trae 冷切换编排 + 进程控制（移植自 trae-switch src/switcher.js / proc.js）。
//!
//! 为什么必须「冷切换」：Trae 运行中会把内存里的登录态回写 storage.json / leveldb，
//! 不关掉进程直接改文件几乎立刻被覆盖 —— 表现为「切了但没生效」。
//!
//! 守护逻辑：拉起后轮询 storage.json，
//!   · 进程没起来 / 凭据缺失 / 落到了**别的** uid → 判定失败，自动回滚并重新拉起
//!   · 观察到的 live uid === 目标 uid                 → 成功
//!   · 无法确定目标 uid 且没观察到写入                → 需要人工确认
//!
//! 载体条目与账号快照复用 `trae_carriers` / `trae_vault`；进程控制用 tasklist /
//! taskkill（不依赖 PowerShell），避免被系统策略拦截。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::modules::config::store_dir;
use crate::modules::trae_carriers::{detect_carrier_entries, overwrite_entry, sanitize_entries};
use crate::modules::trae_discover::{get_client, has_login_state, process_names, storage_json_path, user_data_dir, TraeClient};
use crate::modules::trae_km::{decrypt_km_json, is_km_value, jwt_exp, jwt_user_id};
use crate::modules::trae_synth::{needs_synthesis, synthesize_carrier};
use crate::modules::trae_vault::{restore, uid_of_account};

pub const OUTCOME_ACTIVE: &str = "active";
pub const OUTCOME_ROLLED_BACK: &str = "rolled_back";
pub const OUTCOME_NEEDS_CONFIRM: &str = "needs_confirm";

// ---------------------------------------------------------------------------
// 配置（存于 `<~/.trae-switch-cn>/trae/config.json`）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraeConfig {
    pub active_client: String,
    /// clientKey → 载体条目相对路径列表；空表示用自动探测结果。
    pub fingerprints: HashMap<String, Vec<String>>,
    /// clientKey → 主程序绝对路径；空表示自动探测。
    pub client_exe: HashMap<String, String>,
    /// 切换后自动重新拉起客户端。
    pub auto_relaunch: bool,
    /// 守护超时（毫秒）。
    pub guard_timeout_ms: u64,
    /// 切换前自动把当前 live 存档一份（可在需要时回滚）。
    pub auto_snapshot_before_switch: bool,
}

impl Default for TraeConfig {
    fn default() -> Self {
        Self {
            active_client: "trae-cn".into(),
            fingerprints: HashMap::new(),
            client_exe: HashMap::new(),
            auto_relaunch: true,
            guard_timeout_ms: 25000,
            auto_snapshot_before_switch: true,
        }
    }
}

pub fn config_path() -> PathBuf {
    store_dir().join("trae").join("config.json")
}

pub fn load_config() -> TraeConfig {
    let Ok(text) = std::fs::read_to_string(config_path()) else {
        return TraeConfig::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

pub fn save_config(patch: &Value) -> TraeConfig {
    let mut cur = serde_json::to_value(load_config()).unwrap_or_default();
    if let (Value::Object(map), Value::Object(p)) = (&mut cur, patch) {
        for (k, v) in p {
            map.insert(k.clone(), v.clone());
        }
    }
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&cur).unwrap_or_default());
    serde_json::from_value(cur).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

pub fn switch_log(line: &str) {
    let p = store_dir().join("trae").join("logs").join("switch.log");
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        use std::io::Write;
        let _ = writeln!(f, "[{stamp}] {line}");
    }
}

// ---------------------------------------------------------------------------
// 进程控制（tasklist / taskkill）
// ---------------------------------------------------------------------------

fn run_cmd(program: &str, args: &[String], timeout: Duration) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(_) => return None,
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let out = child.wait_with_output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 返回正在运行的相关进程 [(名称, pid)]（含 ai-agent）。
pub fn list_processes(client: &TraeClient) -> Vec<(String, u32)> {
    let mut names: Vec<String> = process_names(client).iter().map(|s| s.to_string()).collect();
    names.push("ai-agent".into());
    let mut result = Vec::new();
    #[cfg(windows)]
    for name in &names {
        // tasklist 的 /FI 值含空格时不能加引号（实测加引号报 Invalid argument），
        // 不加引号反而能正确匹配 TRAE SOLO CN.exe 这类镜像名。
        let args = vec![
            "/FI".to_string(),
            format!("IMAGENAME eq {name}.exe"),
            "/FO".to_string(),
            "CSV".to_string(),
            "/NH".to_string(),
        ];
        if let Some(out) = run_cmd("tasklist", &args, Duration::from_secs(15)) {
            for line in out.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let mut parts = line.splitn(3, ',');
                let name = parts.next().unwrap_or("").trim_matches('"').to_string();
                let pid: u32 = parts
                    .next()
                    .unwrap_or("")
                    .trim_matches('"')
                    .parse()
                    .unwrap_or(0);
                if pid > 0 {
                    result.push((name, pid));
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        let pattern = names.join("|");
        if let Some(out) = run_cmd("pgrep", &["-af".to_string(), pattern], Duration::from_secs(15)) {
            for line in out.lines() {
                let line = line.trim();
                let mut parts = line.splitn(2, ' ');
                let pid: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let name = parts.next().unwrap_or("").to_string();
                if pid > 0 {
                    result.push((name, pid));
                }
            }
        }
    }
    result
}

/// 该客户端是否在运行（ai-agent 不算）。
pub fn is_running(client: &TraeClient) -> bool {
    list_processes(client)
        .iter()
        .any(|(n, _)| !n.to_lowercase().contains("ai-agent"))
}

/// 结束该客户端的全部进程（含子进程）。返回被结束的进程名列表。
pub fn kill_all(client: &TraeClient) -> Vec<String> {
    let procs = list_processes(client);
    let mut names: Vec<String> = procs.iter().map(|(n, _)| n.clone()).collect();
    names.sort();
    names.dedup();
    #[cfg(windows)]
    for (_name, pid) in procs {
        // 用 /PID 杀，绕开镜像名含空格（TRAE SOLO CN.exe）时 /IM 值在命令行
        // 解析中的错乱问题；/T 连带子进程树，/F 强制。
        let args = vec![
            "/PID".to_string(),
            pid.to_string(),
            "/T".to_string(),
            "/F".to_string(),
        ];
        let _ = run_cmd("taskkill", &args, Duration::from_secs(20));
    }
    #[cfg(not(windows))]
    for name in &names {
        let _ = run_cmd("pkill", &["-9".to_string(), "-f".to_string(), name.clone()], Duration::from_secs(20));
    }
    names
}

/// 等进程全部退出，最多等待 timeout_ms。
pub fn wait_until_stopped(client: &TraeClient, timeout_ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if !is_running(client) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    !is_running(client)
}

/// 解析客户端主程序路径：用户配置优先，其次自动探测。
pub fn resolve_exe(client: &TraeClient, configured: Option<&str>) -> Option<PathBuf> {
    if let Some(c) = configured {
        if !c.trim().is_empty() && Path::new(c.trim()).is_file() {
            return Some(PathBuf::from(c.trim()));
        }
    }
    crate::modules::trae_discover::detect_exe(client)
}

/// 会被 Electron / Node 继承、并**改变客户端主程序行为**的环境变量。
/// 最要命的是 `ELECTRON_RUN_AS_NODE`：Trae 是 Electron 应用，一旦继承到它，
/// 进程会以纯 Node 解释器身份启动、找不到脚本后立刻 exit 0 —— 表现为
/// 「spawn 成功、进程号也拿到了，但客户端根本没出现」。启动时必须清干净。
const CLIENT_ENV_DROP: [&str; 6] = [
    "ELECTRON_RUN_AS_NODE",
    "ELECTRON_NO_ATTACH_CONSOLE",
    "ELECTRON_ENABLE_LOGGING",
    "ELECTRON_ENABLE_STACK_DUMPING",
    "ELECTRON_FORCE_IS_PACKAGED",
    "NODE_OPTIONS",
];

fn clean_env(cmd: &mut Command) {
    for k in CLIENT_ENV_DROP {
        cmd.env_remove(k);
    }
}

/// 内部：按规范参数 spawn 客户端主程序（独立进程，不随本服务退出）。
fn spawn_client(exe: &Path) -> std::io::Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.current_dir(exe.parent().unwrap_or(Path::new(".")));
    clean_env(&mut cmd);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x00000208); // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    }
    cmd.spawn()
}

/// 拉起客户端（同步返回主程序路径）。
pub fn launch(client_key: &str, configured_exe: Option<&str>) -> Result<PathBuf, String> {
    let client = get_client(client_key).ok_or("未知客户端")?;
    let exe = resolve_exe(client, configured_exe)
        .ok_or(format!("未找到 {} 的主程序，请在设置里手动指定路径", client.label))?;
    let _ = spawn_client(&exe);
    Ok(exe)
}

/// 拉起客户端并**确认它真的起来了**（轮询进程表 + 监视子进程是否秒退）。
/// 进程没出现就重试一次，仍失败则抛出带真因的错误，交给上层回滚。
pub fn launch_and_wait(
    client_key: &str,
    configured_exe: Option<&str>,
    on_log: Option<&dyn Fn(&str)>,
) -> Result<(), String> {
    let client = get_client(client_key).ok_or("未知客户端")?;
    let exe = resolve_exe(client, configured_exe)
        .ok_or(format!("未找到 {} 的主程序，请在设置里手动指定路径", client.label))?;

    // 进程刚被强杀时，客户端可能还在收尾（单实例锁/管道未释放）；
    // 立刻重启会被它判成「已有实例」而直接退出，等一下更稳。
    std::thread::sleep(Duration::from_millis(800));

    let mut last_reason = "进程未出现".to_string();
    for attempt in 1..=2u32 {
        let mut child = match spawn_client(&exe) {
            Ok(c) => c,
            Err(e) => {
                last_reason = format!("无法启动进程：{e}");
                break;
            }
        };
        let deadline = Instant::now() + Duration::from_millis(20000);
        let mut exited: Option<i32> = None;
        let mut spawn_err: Option<String> = None;
        loop {
            std::thread::sleep(Duration::from_millis(300));
            if is_running(client) {
                let extra = if attempt > 1 {
                    format!("，第 {attempt} 次尝试")
                } else {
                    String::new()
                };
                if let Some(log) = on_log {
                    log(&format!("客户端已启动{extra}"));
                }
                return Ok(());
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    exited = Some(status.code().unwrap_or(-1));
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    spawn_err = Some(e.to_string());
                    break;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        if let Some(e) = spawn_err {
            last_reason = format!("无法启动进程：{e}");
            break;
        }
        if let Some(code) = exited {
            last_reason = if code == 0 {
                "进程启动后立刻自行退出（exit 0）——常见于继承了 ELECTRON_RUN_AS_NODE 等环境变量".into()
            } else {
                format!("进程启动后立刻退出（exit {code}）")
            };
        }
        if attempt < 2 {
            if let Some(log) = on_log {
                log(&format!("第 {attempt} 次拉起未成功（{last_reason}），重试…"));
            }
        }
    }

    Err(format!(
        "客户端没能启动：{last_reason}。可检查：① 主程序路径是否正确（设置里可手动指定）；② 是否被安全软件拦截；③ 试着手动双击一次客户端，确认它能正常打开。"
    ))
}

/// storage.json 指纹：长度 + 修改时间，用于判断客户端是否真的写入过会话。
pub fn storage_stamp(client: &TraeClient) -> Option<(u64, u128)> {
    let meta = std::fs::metadata(storage_json_path(client)).ok()?;
    let len = meta.len();
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis())
        .unwrap_or(0);
    Some((len, mtime_ms))
}

pub fn stamp_changed(a: Option<(u64, u128)>, b: Option<(u64, u128)>) -> bool {
    match (a, b) {
        (None, None) => false,
        (None, Some(_)) | (Some(_), None) => true,
        (Some(a), Some(b)) => a.0 != b.0 || a.1 != b.1,
    }
}

// ---------------------------------------------------------------------------
// 载体条目
// ---------------------------------------------------------------------------

/// 取该客户端实际生效的载体条目：配置优先，否则自动探测。全局状态条目一律剔除。
pub fn effective_entries(client_key: &str, root_dir: &Path) -> Vec<String> {
    let cfg = load_config();
    let configured = cfg.fingerprints.get(client_key).cloned().unwrap_or_default();
    let from_config = sanitize_entries(&configured);
    if !from_config.is_empty() {
        return from_config;
    }
    sanitize_entries(&detect_carrier_entries(root_dir))
}

// ---------------------------------------------------------------------------
// 登录态解析（describe_account / is_logged_in）
// ---------------------------------------------------------------------------

fn read_storage_value(client: &TraeClient) -> Option<Value> {
    let text = std::fs::read_to_string(storage_json_path(client)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 解析登录态（离线，不联网）。
pub fn describe_account(client_key: &str) -> Value {
    let client = match get_client(client_key) {
        Some(c) => c,
        None => {
            return json!({ "clientKey": client_key, "label": client_key, "loggedIn": false });
        }
    };
    let mut out = json!({
        "clientKey": client.key,
        "label": client.label,
        "hasStorage": false,
        "loggedIn": false,
        "uid": null,
        "username": null,
        "avatarUrl": null,
        "email": null,
        "region": null,
        "host": client.api_host,
        "deviceId": null,
        "machineId": null,
        "devDeviceId": null,
        "tokenExp": 0,
        "refreshExp": 0,
        "tokenExpText": null,
        "refreshExpText": null,
        "clientVersion": null,
        "knownUids": [],
    });
    let Some(storage) = read_storage_value(client) else {
        return out;
    };
    out["hasStorage"] = json!(true);
    let obj = storage.as_object();

    if let Some(dc_key) = obj.and_then(|m| m.keys().find(|k| k.starts_with("iCubeAuthInfo://icube-dc:"))) {
        out["deviceId"] = json!(dc_key.strip_prefix("iCubeAuthInfo://icube-dc:"));
    }
    if let Some(machine) = storage.get("telemetry.machineId").and_then(|v| v.as_str()) {
        out["machineId"] = json!(machine);
    }
    if let Some(dev) = storage.get("telemetry.devDeviceId").and_then(|v| v.as_str()) {
        out["devDeviceId"] = json!(dev);
    }
    if let Some(ver) = storage.get("iCubeLastVersion").and_then(|v| v.as_str()) {
        out["clientVersion"] = json!(ver);
    }

    if let Some(tag) = storage.get("iCubeAuthInfo://usertag").and_then(|v| v.as_str()) {
        if is_km_value(tag) {
            if let Some(t) = decrypt_km_json(tag) {
                if t.is_object() {
                    let uids: Vec<String> = t
                        .as_object()
                        .map(|m| m.keys().cloned().collect())
                        .unwrap_or_default();
                    out["knownUids"] = json!(uids);
                }
            }
        }
    }

    if let Some(auth_raw) = storage.get("iCubeAuthInfo://icube.cloudide").and_then(|v| v.as_str()) {
        if is_km_value(auth_raw) {
            if let Some(auth) = decrypt_km_json(auth_raw) {
                out["loggedIn"] = json!(true);
                let uid = auth
                    .get("userId")
                    .and_then(|v| {
                        v.as_i64()
                            .map(|i| i.to_string())
                            .or_else(|| v.as_str().map(String::from))
                    })
                    .or_else(|| {
                        auth.get("token")
                            .and_then(|t| t.as_str())
                            .and_then(jwt_user_id)
                    });
                if let Some(u) = uid {
                    out["uid"] = json!(u);
                }
                if let Some(host) = auth.get("host").and_then(|v| v.as_str()) {
                    out["host"] = json!(host);
                }
                if let Some(region) = auth.get("userRegion").and_then(|r| r.get("region")).and_then(|v| v.as_str()) {
                    out["region"] = json!(region);
                }
                if let Some(token) = auth.get("token").and_then(|v| v.as_str()) {
                    let exp = jwt_exp(token);
                    out["tokenExp"] = json!(exp);
                    if exp > 0 {
                        let d = chrono::DateTime::from_timestamp_millis(exp);
                        out["tokenExpText"] = json!(d.map(|t| t.format("%Y-%m-%d %H:%M").to_string()));
                    }
                }
                if let Some(exp_str) = auth.get("refreshExpiredAt").and_then(|v| v.as_str()) {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                        out["refreshExp"] = json!(dt.timestamp_millis());
                        out["refreshExpText"] = json!(dt.format("%Y-%m-%d %H:%M").to_string());
                    }
                }
                if let Some(acc) = auth.get("account") {
                    if let Some(u) = acc.get("username").and_then(|v| v.as_str()) {
                        out["username"] = json!(u);
                    }
                    if let Some(a) = acc.get("avatar_url").or_else(|| acc.get("avatarUrl")).and_then(|v| v.as_str()) {
                        out["avatarUrl"] = json!(a);
                    }
                    if let Some(e) = acc.get("email").and_then(|v| v.as_str()) {
                        out["email"] = json!(e);
                    }
                }
            }
        }
    }
    out
}

/// 是否已登录（两把凭据键都在且非空）。
pub fn is_logged_in(client_key: &str) -> bool {
    get_client(client_key).map(has_login_state).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// 切换编排
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SwitchResult {
    pub outcome: String,
    pub account_id: String,
    pub entries: usize,
    pub uid: Option<String>,
    pub message: String,
}

fn make_rollback_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("trae-switch-rollback-{}-{nanos}", std::process::id()))
}

/// 执行冷切换到目标账号。
pub fn switch_to(
    client_key: &str,
    account_id: &str,
    on_progress: Option<&dyn Fn(&str)>,
) -> Result<SwitchResult, String> {
    let cfg = load_config();
    let client = get_client(client_key).ok_or("未知客户端")?;
    let root_dir = user_data_dir(client);
    let entries = effective_entries(client_key, &root_dir);
    if entries.is_empty() {
        return Err("没有探测到任何登录态载体文件，无法切换。请先在该客户端登录一次。".into());
    }

    let log = |m: &str| {
        switch_log(&format!("[{client_key}→{account_id}] {m}"));
        if let Some(cb) = on_progress {
            cb(m);
        }
    };

    // 0) 结束进程
    log("结束 Trae 进程…");
    kill_all(client);
    let stopped = wait_until_stopped(client, 20000);
    if !stopped {
        return Err("Trae 进程未能退出，请手动关闭后重试".into());
    }

    // 1) 当前 live 快照（回滚用）
    let rollback_dir = make_rollback_dir();
    for rel in &entries {
        overwrite_entry(&root_dir, &rollback_dir, rel);
    }
    log("已备份当前登录态（用于失败回滚）");

    // 2) 写回目标账号（凭证账号先以 live 为骨架自动合成载体）
    if needs_synthesis(client_key, account_id) {
        log("该账号是「网页登录」凭证账号，正在以当前登录态为骨架合成客户端载体…");
        match synthesize_carrier(client_key, account_id, &root_dir, &entries, Some(&log)) {
            Ok(_) => {}
            Err(e) => {
                let _ = std::fs::remove_dir_all(&rollback_dir);
                return Err(format!("载体合成失败：{e}"));
            }
        }
        log("载体合成完成，开始写入目标账号登录态…");
    }
    if let Err(e) = restore(client_key, account_id, &root_dir, &entries) {
        for rel in &entries {
            overwrite_entry(&rollback_dir, &root_dir, rel);
        }
        let _ = std::fs::remove_dir_all(&rollback_dir);
        return Err(format!("写入失败，已回滚：{e}"));
    }
    log("已写入目标账号登录态");

    // 3) 拉起 + 守护
    let outcome;
    if cfg.auto_relaunch {
        let baseline = storage_stamp(client);
        let target_uid = uid_of_account(client_key, account_id);

        log("启动 Trae 客户端…");
        if let Err(e) = launch_and_wait(client_key, cfg.client_exe.get(client_key).map(|s| s.as_str()), Some(&log)) {
            for rel in &entries {
                overwrite_entry(&rollback_dir, &root_dir, rel);
            }
            let _ = launch(client_key, cfg.client_exe.get(client_key).map(|s| s.as_str()));
            log("已尝试用原账号重新拉起客户端");
            let _ = std::fs::remove_dir_all(&rollback_dir);
            return Err(format!("启动失败，已回滚：{e}"));
        }

        let timeout = Duration::from_millis(if cfg.guard_timeout_ms > 0 {
            cfg.guard_timeout_ms
        } else {
            25000
        });
        let started_at = Instant::now();
        let mut running_seen = false;
        let mut changed = false;
        while started_at.elapsed() < timeout {
            std::thread::sleep(Duration::from_millis(500));
            if let Some(cb) = on_progress {
                cb(&format!("等待客户端写入登录态…（{}ms）", started_at.elapsed().as_millis()));
            }
            let running = is_running(client);
            if !running {
                // 见过它在跑又消失了 = 客户端自己退了，再等下去没意义
                if running_seen {
                    break;
                }
                continue;
            }
            running_seen = true;
            if stamp_changed(baseline, storage_stamp(client)) {
                changed = true;
                break;
            }
        }

        let creds_ok = is_logged_in(client_key);
        let live_uid = describe_account(client_key).get("uid").and_then(|v| v.as_str()).map(String::from);

        if !running_seen || !creds_ok {
            outcome = OUTCOME_ROLLED_BACK.to_string();
        } else if let (Some(t), Some(l)) = (&target_uid, &live_uid) {
            if t != l {
                log(&format!("当前落到的账号 uid={l}，与目标 uid={t} 不一致"));
                outcome = OUTCOME_ROLLED_BACK.to_string();
            } else {
                outcome = OUTCOME_ACTIVE.to_string();
            }
        } else if changed {
            outcome = OUTCOME_ACTIVE.to_string();
        } else {
            outcome = OUTCOME_NEEDS_CONFIRM.to_string();
        }

        if outcome == OUTCOME_ROLLED_BACK {
            log("判定未进入目标账号，自动回滚…");
            kill_all(client);
            let _ = wait_until_stopped(client, 15000);
            for rel in &entries {
                overwrite_entry(&rollback_dir, &root_dir, rel);
            }
            let _ = launch(client_key, cfg.client_exe.get(client_key).map(|s| s.as_str()));
        }
    } else {
        log("已按设置跳过自动启动，请手动打开 Trae 验证");
        outcome = OUTCOME_NEEDS_CONFIRM.to_string();
    }

    let _ = std::fs::remove_dir_all(&rollback_dir);

    let mut uid = None;
    if outcome == OUTCOME_ACTIVE {
        uid = describe_account(client_key).get("uid").and_then(|v| v.as_str()).map(String::from);
        crate::modules::trae_vault::mark_used(client_key, account_id, uid.clone());
        log("切换成功");
    }

    let message = match outcome.as_str() {
        OUTCOME_ACTIVE => "切换成功".to_string(),
        OUTCOME_ROLLED_BACK => "未进入目标账号，已自动回滚到原账号".to_string(),
        _ => "无法确认是否生效，请手动打开客户端验证".to_string(),
    };
    Ok(SwitchResult {
        outcome,
        account_id: account_id.to_string(),
        entries: entries.len(),
        uid,
        message,
    })
}

/// 回滚到某个已建档账号（本质是切回它）。
pub fn rollback_to(
    client_key: &str,
    account_id: &str,
    on_progress: Option<&dyn Fn(&str)>,
) -> Result<SwitchResult, String> {
    switch_to(client_key, account_id, on_progress)
}
