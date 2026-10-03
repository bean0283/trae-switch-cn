//! 账号资料查询（接口契约对齐青龙签到脚本 checkin_ql.js）：
//!   · `GetUserInfo`（x-cloudide-token 头）拉真实昵称 / UserID / 脱敏手机号；
//!   · `user_current_entitlement_list`（authorization: Cloud-IDE-JWT）拉积分余额。
//!
//! 结果缓存到 `<vault>/<client>/<id>/profile.json`，账号库离线也能展示最近一次
//! 拉取到的昵称与积分；网络失败时静默保留旧缓存，不打断账号库主流程。

use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::modules::config::http_request;
use crate::modules::trae_vault::account_dir;

const USERINFO_PATH: &str = "/cloudide/api/v3/trae/GetUserInfo";
const ENTITLE_PATH: &str = "/trae/api/v2/pay/user_current_entitlement_list";
/// 实测可用域名：签到脚本走 api.trae.cn；oauth 落库的 host 可能是 api.trae.com.cn，
/// 请求失败时按候选列表逐个回退。
const HOSTS: &[&str] = &["https://api.trae.cn", "https://api.trae.com.cn"];

pub fn profile_path(client_key: &str, id: &str) -> PathBuf {
    account_dir(client_key, id).join("profile.json")
}

fn clean_token(token: &str) -> String {
    token.trim().strip_prefix("Cloud-IDE-JWT ").map(String::from).unwrap_or_else(|| token.trim().to_string())
}

/// 生成形如官方客户端的纯数字设备 ID（oauth.json 无 deviceId 时兜底）。
fn gen_device_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{now}{}", now % 997)
}

/// 候选域名（去重）：oauth 落库 host 优先，接口实测域名兜底。
fn candidate_hosts(oauth: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: String| {
        let h = h.trim().trim_end_matches('/').to_string();
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    };
    if let Some(h) = oauth.get("host").and_then(|v| v.as_str()) {
        push(h.to_string());
    }
    for h in HOSTS {
        push((*h).to_string());
    }
    out
}

fn value_str(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| {
        x.as_str()
            .map(String::from)
            .or_else(|| x.as_i64().map(|i| i.to_string()))
    })
}

/// 调 GetUserInfo 拿真实昵称 / UserID / 脱敏手机号。失败返回 None。
async fn fetch_user_info(host: &str, token: &str) -> Option<Value> {
    let mut headers = HashMap::new();
    headers.insert("accept".into(), "*/*".into());
    headers.insert("x-cloudide-token".into(), token.to_string());
    let j = http_request(
        &format!("{host}{USERINFO_PATH}"),
        "POST",
        Some(json!({ "ReqSource": "Lite", "IDEVersion": "0.1.63" })),
        Some(&headers),
    )
    .await;
    let r = j.get("Result")?;
    let user_id = value_str(r.get("UserID"))?;
    if user_id.is_empty() {
        return None;
    }
    Some(json!({
        "user_id": user_id,
        "screen_name": r.get("ScreenName").and_then(|v| v.as_str()).map(str::trim).unwrap_or_default(),
        "mobile": r.get("NonPlainTextMobile").and_then(|v| v.as_str()).unwrap_or_default(),
    }))
}

/// 调 user_current_entitlement_list 算剩余积分（usage_summary 优先，包列表兜底）。
async fn fetch_credits(host: &str, token: &str, device_id: &str) -> Option<i64> {
    let mut headers = HashMap::new();
    headers.insert("authorization".into(), format!("Cloud-IDE-JWT {token}"));
    headers.insert("x-device-id".into(), device_id.to_string());
    headers.insert("x-device-type".into(), "windows".into());
    headers.insert("x-user-region".into(), "CN".into());
    headers.insert("x-market-client-id".into(), "VSCode 1.107.1".into());
    headers.insert("x-app-version".into(), "0.1.63".into());
    headers.insert("app-version".into(), "0.1.63".into());
    headers.insert("package-type".into(), "stable_cn".into());
    headers.insert("accept-language".into(), "zh-CN".into());
    let j = http_request(
        &format!("{host}{ENTITLE_PATH}"),
        "POST",
        Some(json!({ "req_source": 2 })),
        Some(&headers),
    )
    .await;
    if let Some(us) = j.get("usage_summary") {
        if let (Some(total), Some(consumed)) = (
            us.get("total_amount").and_then(|v| v.as_f64()),
            us.get("consumed_amount").and_then(|v| v.as_f64()),
        ) {
            return Some((total - consumed).max(0.0) as i64);
        }
    }
    let packs = j.get("user_entitlement_pack_list").and_then(|v| v.as_array())?;
    let mut remaining: f64 = 0.0;
    for p in packs {
        if p.get("status").and_then(|v| v.as_i64()).unwrap_or(0) != 1 {
            continue;
        }
        let limit = p
            .pointer("/entitlement_base_info/quota/credits_limit")
            .and_then(|v| v.as_f64());
        if let Some(limit) = limit {
            let used = p.pointer("/usage/credits_amount").and_then(|v| v.as_f64());
            remaining += (limit - used.unwrap_or(0.0)).max(0.0);
        }
    }
    Some(remaining as i64)
}

/// 刷新账号资料（昵称 + 积分）并缓存到 profile.json。
/// 网络全部失败时返回 None 且不动旧缓存。oauth 为 read_oauth_account 的返回。
pub async fn refresh_profile(client_key: &str, id: &str, oauth: &Value) -> Option<Value> {
    let raw_token = value_str(oauth.get("token"))?;
    let token = clean_token(&raw_token);
    if token.is_empty() {
        return None;
    }
    let device_id = value_str(oauth.get("deviceId")).unwrap_or_else(gen_device_id);
    for host in candidate_hosts(oauth) {
        let info = fetch_user_info(&host, &token).await;
        let credits = fetch_credits(&host, &token, &device_id).await;
        if info.is_none() && credits.is_none() {
            continue;
        }
        let profile = json!({
            "screen_name": info.as_ref().and_then(|i| i.get("screen_name")).cloned().unwrap_or(Value::Null),
            "user_id": info.as_ref().and_then(|i| i.get("user_id")).cloned().unwrap_or(Value::Null),
            "mobile": info.as_ref().and_then(|i| i.get("mobile")).cloned().unwrap_or(Value::Null),
            "credits": credits.map(|c| json!(c)),
            "host": host,
            "fetched_at": chrono::Local::now().to_rfc3339(),
        });
        let p = profile_path(client_key, id);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&p, serde_json::to_string_pretty(&profile).unwrap_or_default());
        return Some(profile);
    }
    None
}
