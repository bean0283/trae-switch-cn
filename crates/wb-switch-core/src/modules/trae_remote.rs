//! 云端会话操作（移植自 trae-switch src/sessions.js + traeapi.js）。
//!
//! 用账号凭证访问 remote API（`{remote_host}/api/remote/v1/*`），当前用途：
//! 删除本地会话时**同步删除云端任务列表记录**。
//!
//! 凭证材料来源（按优先级）：
//!   1. oauth 档案（`vault/<client>/<id>/oauth.json`，网页登录落库，字段自包含）；
//!   2. carrier 载体档案 / 当前 live 登录态（`storage.json` 的
//!      `iCubeAuthInfo://icube.cloudide` 登录态 + `iCubeAuthInfo://icube-dc:` 设备密钥）。
//!
//! token 过期时用 refreshToken 走 ExchangeToken 设备签名握手续期
//! （签名串与客户端 `_Te()` 一致：METHOD/PATH/ClientID/RefreshToken/Timestamp/Nonce）。

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};

use crate::modules::config::http_request_raw;
use crate::modules::trae_discover::{get_client, storage_json_path, TraeClient};
use crate::modules::trae_km::{decrypt_km_json, is_km_value, jwt_exp, jwt_user_id};
use crate::modules::trae_oauth::{
    read_oauth_account, vault_uid_index, OAUTH_APP_VERSION, OAUTH_EXCHANGE_PATH,
};
use crate::modules::trae_vault::{account_dir, KEY_AUTH, REL_STORAGE};

/// storage.json 里的设备密钥前缀（`iCubeAuthInfo://icube-dc:<deviceId>`）。
const PREFIX_DC: &str = "iCubeAuthInfo://icube-dc:";
/// remote API 请求头用户区域。
const USER_REGION: &str = "cn";
/// ExchangeToken 刷新的默认账号域（traeapi.js 同款）。
const EXCHANGE_DEFAULT_HOST: &str = "https://api.trae.cn";

/// 客户端参数（取自 product.json 的 iCubeApp.authConfig，与 traeapi.js 一致）。
const CLIENT_PROFILES: [(&str, &str, &str); 2] = [
    ("SOLO", "en1oxy7wnw8j9n", "SOLO_PC"),
    ("TRAE", "ono9krqynydwx5", "IDE_PC"),
];

fn profile_of(client_key: &str) -> (&'static str, &'static str, &'static str) {
    if client_key.starts_with("solo") {
        CLIENT_PROFILES[0]
    } else {
        CLIENT_PROFILES[1]
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 云端调用所需凭证材料。
pub struct CloudMaterial {
    pub access_token: String,
    pub refresh_token: String,
    pub device_id: String,
    pub machine_id: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub app_version: String,
    pub profile: &'static str,
    pub client_id: &'static str,
    pub platform_code: &'static str,
    /// ExchangeToken 刷新的账号域（api.trae.cn）。
    pub exchange_host: String,
    /// remote API 域（trae-api-cn.mchost.guru）。
    pub remote_host: String,
}

fn remote_host_of(client: &TraeClient) -> String {
    client.remote_host.trim_end_matches('/').to_string()
}

/// 从 storage.json 文本提取 uid 对应的云端材料（carrier 副本或 live 本体）。
fn material_from_storage(client_key: &str, text: &str, uid: &str) -> Option<CloudMaterial> {
    let obj: Value = serde_json::from_str(text).ok()?;
    let auth_raw = obj.get(KEY_AUTH)?.as_str()?;
    if !is_km_value(auth_raw) {
        return None;
    }
    let auth = decrypt_km_json(auth_raw)?;
    let auth_uid = auth
        .get("uid")
        .and_then(|v| v.as_str().map(String::from))
        .or_else(|| {
            find_value(&auth, &["token", "Token", "accessToken", "access_token", "Jwt", "JWT"])
                .and_then(|t| jwt_user_id(&t))
        })?;
    if auth_uid != uid {
        return None;
    }
    let token = find_value(&auth, &["token", "Token", "accessToken", "access_token", "Jwt", "JWT"])?;
    let refresh = find_value(&auth, &["refreshToken", "RefreshToken", "refresh_token"])?;
    let dc_key = obj.as_object()?.keys().find(|k| k.starts_with(PREFIX_DC))?.clone();
    let dc_raw = obj.get(&dc_key)?.as_str()?;
    if !is_km_value(dc_raw) {
        return None;
    }
    let dc = decrypt_km_json(dc_raw)?;
    let private_key_pem = dc.get("privateKeyPEM").and_then(|v| v.as_str())?.to_string();
    let public_key_pem = dc.get("publicKeyPEM").and_then(|v| v.as_str())?.to_string();
    let device_id = dc_key.strip_prefix(PREFIX_DC)?.to_string();
    if device_id.is_empty() {
        return None;
    }
    let machine_id = obj
        .get("telemetry.machineId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let app_version = obj
        .get("iCubeLastVersion")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| OAUTH_APP_VERSION.to_string());
    let (profile, client_id, platform_code) = profile_of(client_key);
    let client = get_client(client_key)?;
    Some(CloudMaterial {
        access_token: token,
        refresh_token: refresh,
        device_id,
        machine_id,
        private_key_pem,
        public_key_pem,
        app_version,
        profile,
        client_id,
        platform_code,
        exchange_host: EXCHANGE_DEFAULT_HOST.to_string(),
        remote_host: remote_host_of(client),
    })
}

/// 在 JSON 树里找首个非空字符串值（按键名顺序，递归兜底）。
fn find_value(v: &Value, keys: &[&str]) -> Option<String> {
    if v.is_null() {
        return None;
    }
    if let Some(arr) = v.as_array() {
        for x in arr {
            if let Some(hit) = find_value(x, keys) {
                return Some(hit);
            }
        }
        return None;
    }
    if let Some(obj) = v.as_object() {
        for k in keys {
            if let Some(val) = obj.get(*k) {
                if let Some(s) = val.as_str() {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }
        for val in obj.values() {
            if let Some(hit) = find_value(val, keys) {
                return Some(hit);
            }
        }
    }
    None
}

/// 解析 uid → 云端材料。
/// oauth 档案优先（凭证自包含）；其次 carrier 副本 / live 登录态（storage.json）。
pub fn cloud_material_for(client_key: &str, uid: &str) -> Option<CloudMaterial> {
    let client = get_client(client_key)?;
    // 1) oauth 档案
    if let Some((id, _)) = vault_uid_index(client_key).get(uid).cloned() {
        if let Some(oa) = read_oauth_account(client_key, &id) {
            let token = find_value(&oa, &["token", "Token", "accessToken", "access_token", "Jwt", "JWT"])?;
            let refresh = find_value(&oa, &["refreshToken", "RefreshToken", "refresh_token"])?;
            let device_id = find_value(&oa, &["deviceId", "DeviceID", "device_id"])?;
            if token.is_empty() || refresh.is_empty() || device_id.is_empty() {
                return None;
            }
            let (profile, cid, pc) = profile_of(client_key);
            return Some(CloudMaterial {
                access_token: token,
                refresh_token: refresh,
                device_id,
                machine_id: find_value(&oa, &["machineId", "machine_id"]).unwrap_or_default(),
                private_key_pem: find_value(&oa, &["privateKeyPEM", "private_key_pem"])?,
                public_key_pem: find_value(&oa, &["publicKeyPEM", "public_key_pem"]).unwrap_or_default(),
                app_version: find_value(&oa, &["appVersion", "app_version"]).unwrap_or_else(|| OAUTH_APP_VERSION.to_string()),
                profile,
                client_id: cid,
                platform_code: pc,
                exchange_host: find_value(&oa, &["host"]).unwrap_or_else(|| EXCHANGE_DEFAULT_HOST.to_string()),
                remote_host: remote_host_of(client),
            });
        }
    }
    // 2) live 登录态（storage.json 本体）
    if let Ok(text) = std::fs::read_to_string(storage_json_path(client)) {
        if let Some(m) = material_from_storage(client_key, &text, uid) {
            return Some(m);
        }
    }
    // 3) carrier 载体档案（storage.json 副本）
    for id in crate::modules::trae_vault::list_vault_accounts(client_key) {
        let sp = account_dir(client_key, &id).join(REL_STORAGE);
        if let Ok(text) = std::fs::read_to_string(&sp) {
            if let Some(m) = material_from_storage(client_key, &text, uid) {
                return Some(m);
            }
        }
    }
    None
}

/// 设备签名（P-256 ECDSA-SHA256，DER 编码 base64）——客户端 `_Te()` 同款。
fn sign_ecdsa_sha256(pem: &str, msg: &str) -> Result<String, String> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use sha2::Digest;
    let sk = SigningKey::from_pkcs8_pem(pem).map_err(|e| format!("解析设备私钥失败: {e}"))?;
    let digest = sha2::Sha256::digest(msg.as_bytes());
    let sig: p256::ecdsa::Signature = sk.sign(&digest);
    Ok(STANDARD.encode(sig.to_der().as_bytes()))
}

/// 解析 ExchangeToken 刷新响应的 token 字段。
fn parse_refresh_body(body: &Value) -> Option<String> {
    find_value(body, &["Token", "token", "AccessToken", "accessToken"])
        .filter(|s| !s.is_empty())
}

/// 取可用 token：未过期直接用；过期则 refreshToken 设备签名续期。
pub async fn ensure_cloud_token(m: &CloudMaterial) -> Result<String, String> {
    if jwt_exp(&m.access_token) > now_secs() {
        return Ok(m.access_token.clone());
    }
    let base = m.exchange_host.trim_end_matches('/');
    let url = format!("{base}{OAUTH_EXCHANGE_PATH}");
    let ts = now_secs();
    let nonce = crate::modules::trae_oauth::random_hex(32);
    let to_sign = format!(
        "POST\n{}\n{}\n{}\n{}\n{}",
        OAUTH_EXCHANGE_PATH, m.client_id, m.refresh_token, ts, nonce
    );
    let signature = sign_ecdsa_sha256(&m.private_key_pem, &to_sign)?;
    let payload = json!({
        "ClientID": m.client_id,
        "ClientSecret": "",
        "RefreshToken": m.refresh_token,
        "DeviceInfo": {
            "DeviceID": m.device_id,
            "MachineID": if m.machine_id.is_empty() { crate::modules::trae_oauth::random_hex(32) } else { m.machine_id.clone() },
            "PlatformCode": m.platform_code,
            "DeviceType": "PC",
            "DeviceName": std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".into()),
            "DeviceModel": "",
            "ClientVersion": m.app_version,
            "DevicePublicKey": m.public_key_pem.clone(),
            "DeviceBrand": "",
            "DeviceCPU": "",
            "OSInfo": "",
            "OSVersion": "",
        },
        "DeviceProof": { "Signature": signature, "Timestamp": ts, "Nonce": nonce },
        "IDEVersion": m.app_version,
    });
    let mut headers = HashMap::new();
    headers.insert("x-cloudide-token".into(), m.access_token.clone());
    headers.insert("User-Agent".into(), "trae-switch-cn/1.0".into());
    let (status, _, body_text) = http_request_raw(&url, "POST", Some(payload), Some(&headers), None, true).await;
    let body: Value = serde_json::from_str(&body_text).unwrap_or(Value::Null);
    if status >= 200 && status < 300 {
        if let Some(t) = parse_refresh_body(&body) {
            return Ok(t);
        }
        return Err(format!(
            "ExchangeToken 刷新成功但响应中无 token 字段（HTTP {status}）：{}",
            body_text.chars().take(200).collect::<String>()
        ));
    }
    let msg = body
        .get("message")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("Message").and_then(|v| v.as_str()))
        .unwrap_or("未知错误");
    let code = body
        .get("code")
        .or_else(|| body.get("Code"))
        .and_then(|v| v.as_str().map(String::from).or_else(|| v.as_i64().map(|i| i.to_string())))
        .unwrap_or_default();
    Err(format!("ExchangeToken 刷新失败（HTTP {status}{}）：{}", if code.is_empty() { String::new() } else { format!(" / code {code}") }, msg))
}

/// 删除云端会话（任务列表记录）。成功返回 `{ok, http}`；凭证缺失返回错误。
pub async fn delete_cloud_session(client_key: &str, uid: &str, session_id: &str) -> Result<Value, String> {
    let m = cloud_material_for(client_key, uid)
        .ok_or_else(|| format!("账号（uid …{}）没有可用的云端凭证（未通过工具网页登录或备份过登录态）", &uid[uid.len().saturating_sub(6)..]))?;
    let token = ensure_cloud_token(&m).await?;
    let url = format!("{}/api/remote/v1/chat_sessions/{}", m.remote_host, session_id);
    let mut headers = HashMap::new();
    headers.insert("Authorization".into(), format!("Cloud-IDE-JWT {token}"));
    headers.insert("x-device-id".into(), m.device_id);
    headers.insert("X-User-Region".into(), USER_REGION.into());
    headers.insert("Content-Type".into(), "application/json".into());
    headers.insert("User-Agent".into(), "trae-switch-cn/1.0".into());
    let (status, _, body_text) = http_request_raw(&url, "DELETE", None, Some(&headers), None, true).await;
    if status >= 200 && status < 300 {
        return Ok(json!({ "ok": true, "http": status }));
    }
    let body: Value = serde_json::from_str(&body_text).unwrap_or(Value::Null);
    let msg = body
        .get("message")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("Message").and_then(|v| v.as_str()))
        .map(String::from)
        .unwrap_or_else(|| body_text.chars().take(200).collect::<String>());
    let code = body
        .get("code")
        .or_else(|| body.get("Code"))
        .and_then(|v| v.as_str().map(String::from).or_else(|| v.as_i64().map(|i| i.to_string())))
        .unwrap_or_default();
    Err(format!(
        "云端删除失败（HTTP {status}{}）：{}",
        if code.is_empty() { String::new() } else { format!(" / code {code}") },
        msg
    ))
}

/// 该 uid 是否有可用的云端凭证（删除预览提示用，只读不请求）。
pub fn has_cloud_credential(client_key: &str, uid: &str) -> bool {
    cloud_material_for(client_key, uid).is_some()
}

/// 测试用：临时目录辅助。
#[cfg(test)]
pub fn _store_dir() -> std::path::PathBuf {
    store_dir()
}
