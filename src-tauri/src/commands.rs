//! Tauri commands：前端调用的薄包装，对应 trae-switch 原版的账号/记录能力。
//!
//! 覆盖：Trae 客户端发现 / 账号库 / 切换 / 网页登录 / 解密 / 导入 / 删除 / 交接记忆，
//! 外加 relaunch、错误日志等通用命令。

use serde_json::{json, Value};

use tauri::Emitter;
use wb_switch_core::modules::{
    error_log, trae_decrypt, trae_delete, trae_discover, trae_export, trae_handoff, trae_import,
    trae_memory_scan, trae_oauth, trae_remote, trae_switch, trae_vault,
};

// ---------------------------------------------------------------------------
// 通用命令
// ---------------------------------------------------------------------------

/// 启动当前应用的新进程并退出旧进程，用于更新安装完成后的立即重启。
#[tauri::command]
pub fn relaunch_app(_app: tauri::AppHandle) -> Result<(), String> {
    relaunch_app_inner(&_app)
}

/// 重启实现：保留单实例交棒，避免旧进程未退出时新进程抢锁失败。
pub(crate) fn relaunch_app_inner<R: tauri::Runtime>(
    _app: &tauri::AppHandle<R>,
) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|e| format!("无法定位应用程序: {e}"))?;
    let args = std::env::args_os().skip(1);
    // 先放弃单例身份（删除 socket，并在 macOS 上释放 flock）再交棒：否则新进程
    // 可能在旧 listener / 锁消失前连上或抢锁失败，出现「旧进程已退、新进程也退出」
    // 而应用彻底消失。
    #[cfg(desktop)]
    tauri_plugin_single_instance::destroy(_app);
    #[cfg(target_os = "macos")]
    crate::instance_lock::release(_app);
    match std::process::Command::new(executable).args(args).spawn() {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            // 已经放弃单例身份：要么把锁拿回来继续跑，要么退出。
            // 不允许「无锁继续运行」（否则之后再启动就会双开）。
            #[cfg(target_os = "macos")]
            if !crate::instance_lock::reacquire(_app) {
                std::process::exit(0);
            }
            Err(format!("启动应用失败: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// 错误日志（前端崩溃 / 未捕获错误落盘）
// ---------------------------------------------------------------------------

/// 记录一条错误日志（`kind` 白名单：frontend_crash / frontend_unhandled / backend）。
///
/// 只落盘、不返回失败：目录只读、磁盘满等写入失败由 core 静默降级（`let _ =`），
/// 绝不让「记日志」反过来打断前端主流程。
#[tauri::command]
pub async fn log_error(kind: String, message: String, detail: Option<String>) {
    error_log::record(&kind, &message, detail.as_deref().unwrap_or_default());
}

/// 错误日志文件路径（设置页展示用）。
#[tauri::command]
pub fn get_error_log_path() -> String {
    error_log::error_log_path().to_string_lossy().to_string()
}

/// 在文件管理器中定位错误日志；日志尚未生成时改为定位所在目录。
///
/// 走 tauri-plugin-opener 的 Rust API（不依赖前端 capability）；reveal 内部会
/// canonicalize，路径不存在会直接报错，所以这里按「文件 → 目录」逐级回退。
#[tauri::command]
pub fn reveal_error_log(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    let path = error_log::error_log_path();
    // reveal 会 canonicalize，目标不存在就直接失败。日志还没生成时改为定位目录；
    // 目录也不存在（还没写过任何错误）就先建出来，避免按钮第一次点就失败。
    let target = if path.exists() {
        path
    } else {
        match path.parent() {
            Some(dir) => {
                let _ = std::fs::create_dir_all(dir);
                if dir.exists() {
                    dir.to_path_buf()
                } else {
                    path
                }
            }
            None => path,
        }
    };
    app.opener()
        .reveal_item_in_dir(target)
        .map_err(|error| format!("打开日志位置失败: {error}"))
}

// ---------------------------------------------------------------------------
// Trae 模块：客户端发现 / 账号库 / 切换 / 解密 / 导出 / 删除 / 交接记忆
// ---------------------------------------------------------------------------

/// 列出已安装的 Trae 客户端（含登录态与安装路径）。
#[tauri::command]
pub fn trae_list_clients() -> Value {
    json!({ "clients": trae_discover::list_installed_clients() })
}

/// Trae 账号总览：当前登录态（describe_account）+ 账号库已建档列表。
#[tauri::command]
pub async fn trae_account_overview(client_key: String) -> Result<Value, String> {
    if trae_discover::get_client(&client_key).is_none() {
        return Err(format!("未知客户端：{client_key}"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let client = trae_discover::get_client(&client_key).ok_or("未知客户端")?;
        let live = trae_switch::describe_account(&client_key);
        let vault: Vec<Value> = trae_vault::list_vault_accounts(&client_key)
            .iter()
            .map(|id| {
                let meta = trae_vault::read_meta(&client_key, id);
                let kind = meta
                    .as_ref()
                    .map(|m| m.kind.clone())
                    .unwrap_or_else(|| "carrier".into());
                let oauth = if kind == "oauth" {
                    trae_oauth::read_oauth_account(&client_key, id)
                } else {
                    None
                };
                json!({ "id": id, "meta": meta, "kind": kind, "oauth": oauth })
            })
            .collect();
        Ok(json!({
            "clientKey": client_key,
            "loggedIn": live.get("loggedIn").cloned().unwrap_or(json!(false)),
            "running": trae_switch::is_running(client),
            "live": live,
            "vault": vault,
        }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 识别当前登录账号（写入账号库前调用，拿 uid 做归属）。
#[tauri::command]
pub async fn trae_identify_live(client_key: String) -> Result<Value, String> {
    let client = trae_discover::get_client(&client_key).ok_or("未知客户端")?;
    let root_dir = trae_discover::user_data_dir(client);
    tauri::async_runtime::spawn_blocking(move || {
        trae_vault::identify(&client_key, &root_dir).ok_or_else(|| {
            "未识别到当前登录账号（storage.json 中无可读账号信息），请先登录该客户端".to_string()
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 把当前登录态备份进账号库（写入前自动识别 uid）。
#[tauri::command]
pub async fn trae_backup_account(client_key: String, account_id: String) -> Result<Value, String> {
    let client = trae_discover::get_client(&client_key).ok_or("未知客户端")?;
    let root_dir = trae_discover::user_data_dir(client);
    tauri::async_runtime::spawn_blocking(move || {
        let entries = trae_switch::effective_entries(&client_key, &root_dir);
        if entries.is_empty() {
            return Err("没有探测到任何登录态载体文件，无法备份。请先在该客户端登录一次。".into());
        }
        let verified = trae_vault::identify(&client_key, &root_dir)
            .and_then(|v| v.get("uid").and_then(|u| u.as_str()).map(String::from));
        match trae_vault::backup(&client_key, &account_id, &root_dir, &entries) {
            Ok(meta) => Ok(json!({ "ok": true, "accountId": account_id, "verifiedUid": verified, "meta": meta })),
            Err(e) => Err(e),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 切换到账号库中的某账号（冷切换：终止进程 → 还原载体 → 重启 → daemon 判定）。
#[tauri::command]
pub async fn trae_switch_to(client_key: String, account_id: String) -> Result<Value, String> {
    if trae_discover::get_client(&client_key).is_none() {
        return Err(format!("未知客户端：{client_key}"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let progress: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let r = trae_switch::switch_to(&client_key, &account_id, Some(&|m| {
            progress.lock().unwrap().push(m.to_string());
        }));
        let progress = progress.into_inner().unwrap_or_default();
        match r {
            Ok(sr) => {
                let mut v = serde_json::to_value(&sr).map_err(|e| e.to_string())?;
                v["progress"] = json!(progress);
                Ok(v)
            }
            Err(e) => Err(format!("{e}\n{}", progress.join("\n"))),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 回滚到某账号（本质是切回它，用于切换异常后的恢复）。
#[tauri::command]
pub async fn trae_rollback_to(client_key: String, account_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let progress: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let r = trae_switch::rollback_to(&client_key, &account_id, Some(&|m| {
            progress.lock().unwrap().push(m.to_string());
        }));
        let progress = progress.into_inner().unwrap_or_default();
        match r {
            Ok(sr) => {
                let mut v = serde_json::to_value(&sr).map_err(|e| e.to_string())?;
                v["progress"] = json!(progress);
                Ok(v)
            }
            Err(e) => Err(format!("{e}\n{}", progress.join("\n"))),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 从账号库删除某个账号的备份（只删本地档案，不影响客户端登录态）。
#[tauri::command]
pub async fn trae_remove_account(client_key: String, account_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trae_vault::remove_account(&client_key, &account_id)?;
        Ok(json!({ "ok": true }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 重命名账号库条目（按账号名管理）。
#[tauri::command]
pub async fn trae_rename_account(client_key: String, from_id: String, to_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let new_id = trae_vault::rename_account(&client_key, &from_id, &to_id)?;
        Ok(json!({ "ok": true, "id": new_id }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 导出账号备份为自包含 JSON（文件内容 base64 内联）。
#[tauri::command]
pub async fn trae_export_account(client_key: String, account_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || trae_vault::export_account(&client_key, &account_id))
        .await
        .map_err(|e| e.to_string())?
}

/// 导入账号备份（自包含 JSON，preferName 可选覆盖账号名）。
#[tauri::command]
pub async fn trae_import_account(client_key: String, payload: Value, prefer_name: Option<String>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (id, count) = trae_vault::import_account(&client_key, &payload, prefer_name.as_deref())?;
        Ok(json!({ "ok": true, "id": id, "files": count }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 已存盘的 SQLCipher 密钥（供状态展示）。
#[tauri::command]
pub fn trae_saved_key(client_key: String) -> Value {
    json!({ "clientKey": client_key, "key": trae_memory_scan::load_saved_key(&client_key) })
}

/// 一键：扫描进程内存提密钥 → 校验 HMAC → 解密整库到明文 SQLite。
#[tauri::command]
pub async fn trae_scan_and_decrypt(client_key: String) -> Result<Value, String> {
    let client = trae_discover::get_client(&client_key).ok_or("未知客户端")?;
    let db = trae_discover::database_path(client);
    if !db.exists() {
        return Err(format!("未找到数据库：{}", db.display()));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let progress: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let scan = trae_memory_scan::scan_for_key(&client_key, &db, Some(&|m| {
            progress.lock().unwrap().push(m.to_string());
        }))
        .map_err(|e| {
            let p = progress.lock().unwrap().join("\n");
            format!("{e}\n{p}")
        })?;
        if !scan.found {
            return Err(format!("{}\n{}", scan.message, progress.lock().unwrap().join("\n")));
        }
        let key = scan.key.clone().unwrap_or_default();
        trae_memory_scan::save_key(&client_key, &key).map_err(|e| format!("保存密钥失败：{e}"))?;
        let out = trae_export::decrypted_db_path(&client_key);
        let report = trae_decrypt::decrypt_database(&db, &key, &out, Some(&|m| {
            progress.lock().unwrap().push(m.to_string());
        }))
        .map_err(|e| {
            let p = progress.lock().unwrap().join("\n");
            format!("{e}\n{p}")
        })?;
        Ok(json!({
            "scan": scan,
            "report": report,
            "decryptedDb": out.to_string_lossy().into_owned(),
            "progress": progress.into_inner().unwrap_or_default(),
        }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 用已存密钥直接解密（跳过内存扫描，密钥过期会报 HMAC 失败）。
#[tauri::command]
pub async fn trae_decrypt_with_saved_key(client_key: String) -> Result<Value, String> {
    let client = trae_discover::get_client(&client_key).ok_or("未知客户端")?;
    let db = trae_discover::database_path(client);
    let key = trae_memory_scan::load_saved_key(&client_key).ok_or("没有已存密钥，请先运行「扫描密钥并解密」")?;
    tauri::async_runtime::spawn_blocking(move || {
        let out = trae_export::decrypted_db_path(&client_key);
        let report = trae_decrypt::decrypt_database(&db, &key, &out, None)
            .map_err(|e| format!("{e}"))?;
        Ok(json!({ "report": report, "decryptedDb": out.to_string_lossy().into_owned() }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 解密库状态（是否已生成 + 表行数概览）。
#[tauri::command]
pub async fn trae_decrypted_status(client_key: String) -> Value {
    let out = trae_export::decrypted_db_path(&client_key);
    json!({
        "clientKey": client_key,
        "exists": out.exists(),
        "path": out.to_string_lossy().into_owned(),
        "tables": if out.exists() { trae_decrypt::list_tables(&out) } else { Vec::<trae_decrypt::TableStat>::new() },
    })
}

/// Trae 会话列表（解密库，按最后活动倒序）。
#[tauri::command]
pub async fn trae_list_sessions(client_key: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Ok(json!({ "sessions": trae_export::list_sessions(&client_key)? }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 单会话详情（标题 / 轮数 / 完整对话，供记录页预览）。
#[tauri::command]
pub async fn trae_session_detail(client_key: String, session_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || trae_export::session_detail(&client_key, &session_id))
        .await
        .map_err(|e| e.to_string())?
}

/// 导出单个会话为 MD 文件（导出目录内自动去重命名）。
#[tauri::command]
pub async fn trae_export_session(client_key: String, session_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Ok(json!(trae_export::export_session(&client_key, &session_id)?))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 一键导出全部会话为 zip（可跨数据源）。
#[tauri::command]
pub async fn trae_export_all(sources: Vec<String>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Ok(json!(trae_export::export_all(&sources)?))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 账号维度导入候选：全部本机账号（vault + 解密库 local + 当前登录态）。
/// 不排除所选会话的归属账号，改用 `is_source` 标记同客户端同归属的候选（前端禁用）。
#[tauri::command]
pub fn trae_import_candidates(exclude: String, session_id: Option<String>) -> Value {
    let owner = session_id
        .as_deref()
        .and_then(|sid| trae_import::session_owner_uid(&exclude, sid));
    json!({
        "candidates": trae_import::list_account_candidates(&exclude, owner.as_deref()),
        "hints": trae_import::client_hints(),
    })
}

/// 目标账号导入就绪状态探测（不写库）。
#[tauri::command]
pub async fn trae_import_inspect(client_key: String, account_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || trae_import::inspect_account(&client_key, &account_id))
        .await
        .map_err(|e| e.to_string())?
}

/// 跨账号导入会话：源账号（已解密）→ 目标账号本地库。
/// `uid` 为目标账号 uid；同客户端跨账号时为同库复制（新 id）。
/// 进度通过 `trae-import-progress` 事件推送。
#[tauri::command]
pub async fn trae_import_run(
    app: tauri::AppHandle,
    src: String,
    dst: String,
    uid: Option<String>,
    sessions: Vec<String>,
) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = trae_import::import_sessions(&src, &dst, uid.as_deref(), &sessions, Some(&|m| {
            let _ = app.emit("trae-import-progress", json!({ "line": m }));
        }))?;
        Ok(json!(result))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 删除预览：标题 / 各表行数 / 磁盘文件（只读，不删任何东西）。
#[tauri::command]
pub async fn trae_delete_info(client_key: String, session_id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || trae_delete::delete_info(&client_key, &session_id))
        .await
        .map_err(|e| e.to_string())?
}

/// 彻底删除会话：整库备份 → 写实时加密库删行 → 同步删解密库 → 文件移入回收站，
/// 之后再尝试同步删除云端任务列表记录（云端失败仅提示，不影响本地删除结果）。
#[tauri::command]
pub async fn trae_delete_session(client_key: String, session_id: String) -> Result<Value, String> {
    // 归属账号必须先于本地删除解析（本地删除会同步清掉解密库里的会话行）
    let owner_uid = trae_import::session_owner_uid(&client_key, &session_id);
    let progress: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let local = tauri::async_runtime::spawn_blocking({
        let client_key = client_key.clone();
        let session_id = session_id.clone();
        let progress = progress.clone();
        move || {
            trae_delete::delete_session(&client_key, &session_id, Some(&|m| {
                progress.lock().unwrap().push(m.to_string());
            }))
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    let mut v = match local {
        Ok(v) => v,
        Err(e) => return Err(format!("{e}\n{}", progress.lock().unwrap().join("\n"))),
    };

    // 云端同步删除（失败仅提示：本地删除已完成，不受影响）
    let cloud = match owner_uid.as_deref() {
        Some(uid) if trae_remote::has_cloud_credential(&client_key, uid) => {
            progress.lock().unwrap().push(format!(
                "同步删除云端任务列表记录（uid …{}）…",
                &uid[uid.len().saturating_sub(6)..]
            ));
            match trae_remote::delete_cloud_session(&client_key, uid, &session_id).await {
                Ok(r) => {
                    progress.lock().unwrap().push("云端记录已删除".into());
                    json!({
                        "attempted": true,
                        "ok": true,
                        "http": r.get("http").cloned().unwrap_or(Value::Null),
                    })
                }
                Err(e) => {
                    progress.lock().unwrap().push(format!(
                        "云端删除失败（已忽略，本地删除不受影响）：{e}"
                    ));
                    json!({ "attempted": true, "ok": false, "error": e })
                }
            }
        }
        Some(uid) => {
            progress.lock().unwrap().push(format!(
                "账号（uid …{}）无云端凭证，仅删除本地记录",
                &uid[uid.len().saturating_sub(6)..]
            ));
            json!({ "attempted": false, "reason": "no_credential" })
        }
        None => {
            progress.lock().unwrap().push("会话归属账号未知，仅删除本地记录".into());
            json!({ "attempted": false, "reason": "no_owner" })
        }
    };
    v["cloud"] = cloud;
    v["progress"] = json!(progress.lock().unwrap().clone());
    Ok(v)
}

/// 交接记忆预览：解密库自动生成条目 → 组装文档，报告落点，不落盘。
#[tauri::command(rename_all = "camelCase")]
pub async fn trae_handoff_preview(
    client_key: String,
    project_path: Option<String>,
    session_ids: Option<Vec<String>>,
    next_steps: Option<Vec<String>>,
    key_files: Option<Vec<String>>,
    note: Option<String>,
) -> Result<Value, String> {
    if trae_discover::get_client(&client_key).is_none() {
        return Err(format!("未知客户端：{client_key}"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        trae_handoff::handoff_preview(
            &client_key,
            project_path.as_deref(),
            session_ids,
            next_steps.unwrap_or_default(),
            key_files.unwrap_or_default(),
            note.as_deref(),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 写入交接记忆：项目工作目录 + 项目规则 + Trae 记忆库 topics 追加 + 工具目录归档。
#[tauri::command(rename_all = "camelCase")]
pub async fn trae_handoff_write(
    client_key: String,
    project_path: Option<String>,
    session_ids: Option<Vec<String>>,
    next_steps: Option<Vec<String>>,
    key_files: Option<Vec<String>>,
    note: Option<String>,
) -> Result<Value, String> {
    if trae_discover::get_client(&client_key).is_none() {
        return Err(format!("未知客户端：{client_key}"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        trae_handoff::handoff_write(
            &client_key,
            project_path.as_deref(),
            session_ids,
            next_steps.unwrap_or_default(),
            key_files.unwrap_or_default(),
            note.as_deref(),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

// ---------------------------------------------------------------------------
// Trae 网页（OAuth）登录
// ---------------------------------------------------------------------------

/// 起 Trae 网页登录回环监听，返回授权页 URL（不自动打开浏览器，交给调用方决定）。
#[tauri::command]
pub fn trae_oauth_start(client_key: String, name: Option<String>) -> Result<Value, String> {
    trae_oauth::start_loopback(&client_key, name.as_deref())
}

/// Trae 网页登录状态（前端约 1.5s 轮询一次；收到回调时在此驱动完成 token 交换）。
#[tauri::command]
pub async fn trae_oauth_status() -> Value {
    if let Some(url) = trae_oauth::take_callback_url() {
        return trae_oauth::complete_login_from_callback(&url, None, None).await;
    }
    trae_oauth::oauth_status()
}

/// 停止 Trae 网页登录监听（未启动时幂等）。同时清掉落盘的登录会话。
#[tauri::command]
pub fn trae_oauth_stop() -> Value {
    trae_oauth::stop_loopback();
    json!({ "ok": true })
}

/// 查询是否有「已落盘但本进程没在监听」的登录会话（服务重启 / 弹层关掉后）。
#[tauri::command]
pub fn trae_oauth_pending() -> Value {
    json!({ "pending": trae_oauth::pending_login() })
}

/// 手动粘贴授权页回调 URL 完成登录（不依赖回环监听；凭落盘的 verifier 交换）。
#[tauri::command]
pub async fn trae_oauth_manual(client_key: String, name: Option<String>, callback_url: String) -> Value {
    trae_oauth::complete_manual(&client_key, name.as_deref(), &callback_url).await
}

/// 打开 Trae 授权页：默认系统浏览器 / 私密窗口（指定浏览器 key）。
#[tauri::command]
pub fn trae_oauth_open_url(
    url: String,
    private: Option<bool>,
    browser: Option<String>,
) -> Result<Value, String> {
    if private.unwrap_or(false) {
        let info = trae_oauth::open_private(&url, browser.as_deref())?;
        return Ok(json!({ "ok": true, "private": true, "browser": info.label, "browserKey": info.key }));
    }
    trae_oauth::open_in_browser(&url)?;
    Ok(json!({ "ok": true, "private": false }))
}

/// 本机可用的浏览器列表（私密窗口打开用）。
#[tauri::command]
pub fn trae_oauth_browsers() -> Value {
    json!({ "browsers": trae_oauth::detect_browsers() })
}

/// 导入本地登录态：解密指定客户端 storage.json 的授权条目，落库为凭证账号。
#[tauri::command]
pub fn trae_import_local_login(client_key: String) -> Result<Value, String> {
    trae_oauth::import_local_login(&client_key)
}

/// 一键导入：扫描全部已安装客户端，收集每个客户端的本地登录态。
#[tauri::command]
pub fn trae_import_all_local_logins() -> Value {
    trae_oauth::import_all_local_logins()
}
