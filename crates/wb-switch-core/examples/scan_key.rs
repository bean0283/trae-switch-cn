//! 临时验证 7：全量扫描 + 对参考脚本找到的密钥地址做上下文读取，与 Python 参考对照。
use std::path::Path;

use wb_switch_core::modules::trae_memory_scan;

fn main() {
    let db = Path::new(
        r"C:\Users\11970\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent\database.db",
    );
    let client = "solo-cn";
    println!("== scan_for_key({client}) ==");
    match trae_memory_scan::scan_for_key(client, db, Some(&|m| println!("  [prog] {m}"))) {
        Ok(r) => {
            println!(
                "RESULT found={} key={:?} addr={:?} candidates={} scanned={}MB elapsed={}ms pid={:?} msg={}",
                r.found,
                r.key,
                r.address,
                r.candidates,
                r.scanned_mb,
                r.elapsed_ms,
                r.pid,
                r.message
            );
            if r.found {
                let key = r.key.clone().unwrap_or_default();
                println!("== decrypt_database ==");
                let out = std::path::PathBuf::from(
                    r"D:\htw\签到\workbuddy-switch-cn\scan_key_decrypted.db",
                );
                match wb_switch_core::modules::trae_decrypt::decrypt_database(
                    db,
                    &key,
                    &out,
                    Some(&|m| println!("  [prog] {m}")),
                ) {
                    Ok(report) => {
                        println!("DECRYPT OK pages={} bytes={} hmac_ok={} elapsed={}ms tables={:?}", report.pages, report.total_bytes, report.hmac_ok, report.elapsed_ms, report.tables);
                        let _ = std::fs::remove_file(&out);
                    }
                    Err(e) => println!("DECRYPT ERR {e}"),
                }
            }
        }
        Err(e) => println!("RESULT ERR {e}"),
    }

    let addr_arg = std::env::args().nth(1);
    if let Some(a) = addr_arg {
        let addr = u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0);
        let key = "3605f6691095a993f03d5009c918352ef5be31ae31e8f000212b81ff058da773";
        println!("\n== diag_read_at 0x{addr:X} ==");
        for line in trae_memory_scan::diag_read_at(client, addr, key) {
            println!("  {line}");
        }
    }
}
