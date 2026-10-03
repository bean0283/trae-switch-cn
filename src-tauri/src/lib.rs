// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use tauri::Manager;
mod commands;
#[cfg(target_os = "macos")]
mod instance_lock;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // 单实例互斥必须最先注册：`Builder::build()` 按注册顺序 initialize_plugins，
    // 插件 setup 命中已有实例会直接 `std::process::exit(0)`，因此第二个进程在
    // 建主窗口之前就已退出；这里把既有窗口弹出到前台。
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }));
    }

    builder = builder.plugin(tauri_plugin_opener::init());

    let app = builder
        .setup(|_app| {
            #[cfg(target_os = "macos")]
            instance_lock::acquire_or_exit(_app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::relaunch_app,
            commands::log_error,
            commands::get_error_log_path,
            commands::reveal_error_log,
            commands::trae_list_clients,
            commands::trae_account_overview,
            commands::trae_identify_live,
            commands::trae_backup_account,
            commands::trae_switch_to,
            commands::trae_rollback_to,
            commands::trae_remove_account,
            commands::trae_rename_account,
            commands::trae_export_account,
            commands::trae_import_account,
            commands::trae_saved_key,
            commands::trae_scan_and_decrypt,
            commands::trae_decrypt_with_saved_key,
            commands::trae_decrypted_status,
            commands::trae_list_sessions,
            commands::trae_session_detail,
            commands::trae_export_session,
            commands::trae_export_all,
            commands::trae_import_candidates,
            commands::trae_import_inspect,
            commands::trae_import_run,
            commands::trae_delete_info,
            commands::trae_delete_session,
            commands::trae_handoff_preview,
            commands::trae_handoff_write,
            commands::trae_oauth_start,
            commands::trae_oauth_status,
            commands::trae_oauth_stop,
            commands::trae_oauth_pending,
            commands::trae_oauth_manual,
            commands::trae_oauth_open_url,
            commands::trae_oauth_browsers,
            commands::trae_import_local_login,
            commands::trae_import_all_local_logins,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|_app_handle, _event| {});
}
