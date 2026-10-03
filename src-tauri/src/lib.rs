// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use tauri::{Manager, WindowEvent};
mod commands;
#[cfg(target_os = "macos")]
mod instance_lock;

/// 右下角托盘：关闭窗口时隐藏到托盘（不退出），托盘菜单可恢复 / 真正退出。
fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    let tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().expect("缺省窗口图标").clone())
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    // 保持托盘存活：TrayIcon 被 drop 会从系统托盘消失
    app.manage(tray);
    Ok(())
}

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
        .setup(|app| {
            #[cfg(target_os = "macos")]
            instance_lock::acquire_or_exit(app.handle());
            build_tray(app.handle())?;
            Ok(())
        })
        // 点窗口关闭按钮：隐藏到托盘，不退出程序
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::relaunch_app,
            commands::log_error,
            commands::get_error_log_path,
            commands::reveal_error_log,
            commands::reveal_path,
            commands::trae_export_dir,
            commands::trae_list_clients,
            commands::trae_account_overview,
            commands::trae_refresh_profile,
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
