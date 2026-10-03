//! Trae 网页（OAuth）登录（移植自 trae-switch src/oauth.js）。
//!
//! 与「载体切换」的关系：网页登录本身只拿账号**凭证**（token / refreshToken / 设备身份），
//! 不写任何客户端登录态文件。因此登录得到的账号（kind=oauth）：
//!   - 立即可用于签到 / 额度 / 用量 / 后续 Token 续期
//!   - 不产生可切换的客户端载体；切换入口对这类账号给出明确指引
//!
//! 流程（对齐 Trae IDE 授权页实测形态）：
//!   1. 生成 PKCE(verifier + S256 challenge) 与 login_trace_id（兼作 CSRF 绑定值）
//!   2. 本机 127.0.0.1:17388 起短生命周期 HTTP 监听 /authorize
//!   3. 系统浏览器打开授权页，auth_callback_url 指向本机回环地址
//!   4. 授权完成后浏览器 302 回本机，带 authCodeInfo(JSON)/userInfo(JSON)/loginTraceID/host
//!   5. AuthCode + CodeVerifier 调 ${host}/trae/api/v3/oauth/ExchangeToken 换 token
//!   6. 落库为 kind='oauth' 的账号；浏览器展示中文结果页
//!
//! 已固化的坑（勿随意改）：
//!   - client_id 必须 ono9krqynydwx5（IDE_PC）。SOLO 的 en1oxy7wnw8j9n 会让授权页
//!     停在 billing status 之后无后续、不回跳。
//!   - device_id 必须与 DevicePublicKey 同源，否则服务端 20403(Device not match)
//!     / 20405(Device proof required)。
//!   - ExchangeToken 请求头 x-cloudide-token 必须为空字符串。
//!   - AuthCode 场景**不发 DeviceProof**（那是 refreshToken 刷新场景的结构）。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use crate::modules::config::store_dir;
use crate::modules::trae_discover::{get_client, storage_json_path};
use crate::modules::trae_km::{decrypt_km_json, is_km_value, jwt_exp, jwt_user_id};
use crate::modules::trae_vault::{account_dir, list_vault_accounts, read_meta, sanitize_name, REL_STORAGE};

// ───────────────────────── 协议常量（Trae IDE 授权页实测形态） ─────────────────────────

pub const OAUTH_CLIENT_ID: &str = "ono9krqynydwx5";
pub const OAUTH_APP_ID: &str = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8";
pub const OAUTH_PLUGIN_VERSION: &str = "2.3.83560";
pub const OAUTH_APP_VERSION: &str = "3.3.100";
pub const OAUTH_PLATFORM_CODE: &str = "IDE_PC";
pub const OAUTH_LOOPBACK_PORT: u16 = 17388;
/** 默认 API 主机；回调里的 host 参数会覆盖它。 */
pub const OAUTH_DEFAULT_HOST: &str = "https://api.trae.com.cn";
/** AuthCode 换 Token 的路径 —— 以 Trae 客户端本体为准（main.js 内 exchangeTokenByAuthCode）。 */
pub const OAUTH_EXCHANGE_PATH: &str = "/trae/api/v3/oauth/ExchangeToken";
pub const OAUTH_PAGE: &str = "https://www.trae.cn/authorization";
const PREFIX_DC: &str = "iCubeAuthInfo://icube-dc:";
const KEY_AUTH: &str = "iCubeAuthInfo://icube.cloudide";
/** 仅国内版支持网页登录（国际版授权页参数体系不同，未取证）。 */
pub const OAUTH_CLIENTS: [&str; 2] = ["trae-cn", "solo-cn"];

/** 回环监听等待授权的最长时长（5 分钟），到点自动关闭并清掉落盘会话。 */
const WAIT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/** 落盘会话有效期（30 分钟）：超过后凭 verifier 交换被判定过期。 */
const PENDING_TTL_MS: i64 = 30 * 60 * 1000;

// ───────────────────────── 小工具 ─────────────────────────

/// 生成 n 字节的十六进制随机串（n 为字符数；奇数时末尾截断）。
pub fn random_hex(chars: usize) -> String {
    let mut buf = vec![0u8; (chars + 1) / 2];
    let _ = getrandom::getrandom(&mut buf);
    let mut s = buf.iter().map(|b| format!("{b:02x}")).collect::<String>();
    s.truncate(chars);
    s
}

fn random_digits(n: usize) -> String {
    let mut s = String::new();
    while s.len() < n {
        let mut b = [0u8; 4];
        let _ = getrandom::getrandom(&mut b);
        for x in b {
            s.push(char::from(b'0' + (x % 10)));
            if s.len() >= n {
                break;
            }
        }
    }
    s
}

/// PKCE：verifier 为 64 位 hex；challenge = BASE64URL-NOPAD(SHA256(verifier))。
pub fn pkce_pair() -> (String, String) {
    let verifier = random_hex(64);
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    (verifier, challenge)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "Windows-PC".into())
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ───────────────────────── 日志 ─────────────────────────

fn oauth_log(line: &str) {
    let p = store_dir().join("trae").join("logs").join("oauth.log");
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "[{stamp}] {line}");
    }
}

// ───────────────────────── 设备身份 ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthDevice {
    pub device_id: String,
    pub machine_id: String,
    pub private_key_pem: Option<String>,
    pub public_key_pem: Option<String>,
    pub app_version: String,
    pub source: String,
}

/// 从 storage.json 解设备密钥（不要求已登录，只要 icube-dc 键在）。
fn device_from_storage(storage: &Value) -> Option<OAuthDevice> {
    let obj = storage.as_object()?;
    let dc_key = obj.keys().find(|k| k.starts_with(PREFIX_DC))?;
    let raw = obj.get(dc_key)?.as_str()?;
    if !is_km_value(raw) {
        return None;
    }
    let keys = decrypt_km_json(raw)?;
    let private_key_pem = keys.get("privateKeyPEM").and_then(|v| v.as_str()).map(String::from)?;
    let public_key_pem = keys.get("publicKeyPEM").and_then(|v| v.as_str()).map(String::from)?;
    Some(OAuthDevice {
        device_id: dc_key.strip_prefix(PREFIX_DC).map(String::from).unwrap_or_default(),
        machine_id: obj
            .get("telemetry.machineId")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default(),
        private_key_pem: Some(private_key_pem),
        public_key_pem: Some(public_key_pem),
        app_version: obj
            .get("iCubeLastVersion")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| OAUTH_APP_VERSION.to_string()),
        source: String::new(), // 调用方填充
    })
}

fn read_storage_safe(client_key: &str) -> Option<Value> {
    let client = get_client(client_key)?;
    let text = std::fs::read_to_string(storage_json_path(client)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 选定一个稳定的设备身份。
///
/// 优先复用本机已有客户端的 icube 设备密钥：服务端把 device_id 与 DevicePublicKey
/// 绑定校验，复用同一套凭据可以让网页登录得到的 JWT 与客户端内登录的设备一致，
/// 避免被判异动。全机都没有设备密钥时兜底自建 P-256 设备身份（
/// [`load_or_create_self_device`]），不依赖先启动一次 Trae 客户端。
pub fn resolve_oauth_device(prefer_client: Option<&str>) -> Result<OAuthDevice, String> {
    let mut order: Vec<&str> = Vec::new();
    if let Some(p) = prefer_client {
        order.push(p);
    }
    for k in OAUTH_CLIENTS {
        if Some(k) != prefer_client {
            order.push(k);
        }
    }
    let all: Vec<&str> = crate::modules::trae_discover::CLIENTS.iter().map(|c| c.key).collect();
    for k in all {
        if !order.contains(&k) {
            order.push(k);
        }
    }
    for key in order {
        if let Some(storage) = read_storage_safe(key) {
            if let Some(mut dev) = device_from_storage(&storage) {
                if dev.machine_id.is_empty() {
                    dev.machine_id = random_hex(32);
                }
                dev.source = format!("{key}（客户端设备密钥）");
                return Ok(dev);
            }
        }
    }
    Ok(load_or_create_self_device())
}

/// 自建设备身份（全机无客户端设备密钥时的兜底），落在自身数据目录，保持稳定。
/// 与 trae-switch 原版 loadOrCreateSelfDevice 对齐：首次生成后复用同一套
/// device_id + P-256 密钥对，避免每次登录都被服务端判为异动。
fn load_or_create_self_device() -> OAuthDevice {
    let p = store_dir().join("trae").join("oauth_device.json");
    if let Ok(text) = std::fs::read_to_string(&p) {
        if let Ok(j) = serde_json::from_str::<Value>(&text) {
            let device_id = j.get("deviceId").and_then(|v| v.as_str()).unwrap_or("");
            let private_key_pem = j.get("privateKeyPEM").and_then(|v| v.as_str());
            let public_key_pem = j.get("publicKeyPEM").and_then(|v| v.as_str());
            if !device_id.is_empty() && private_key_pem.is_some() && public_key_pem.is_some() {
                return OAuthDevice {
                    device_id: device_id.to_string(),
                    machine_id: j.get("machineId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    private_key_pem: private_key_pem.map(String::from),
                    public_key_pem: public_key_pem.map(String::from),
                    app_version: j
                        .get("appVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or(OAUTH_APP_VERSION)
                        .to_string(),
                    source: "自建设备".into(),
                };
            }
        }
    }
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    let secret = p256::SecretKey::random(&mut OsRng);
    let private_key_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map(|s| s.to_string())
        .unwrap_or_default();
    let public_key_pem = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap_or_default();
    let dev = OAuthDevice {
        device_id: random_digits(16),
        machine_id: random_hex(32),
        private_key_pem: Some(private_key_pem.clone()),
        public_key_pem: Some(public_key_pem.clone()),
        app_version: OAUTH_APP_VERSION.to_string(),
        source: "自建设备（已生成）".into(),
    };
    // 持久化失败不阻断：本次会话内仍可用
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        &p,
        serde_json::to_string_pretty(&json!({
            "deviceId": dev.device_id,
            "machineId": dev.machine_id,
            "privateKeyPEM": private_key_pem,
            "publicKeyPEM": public_key_pem,
            "appVersion": dev.app_version,
        }))
        .unwrap_or_default(),
    );
    dev
}

// ───────────────────────── 登录 URL / 回调 ─────────────────────────

/// 构造授权页登录 URL（参数形态与真实 Trae IDE 登录页一致）。
pub fn build_login_url(device: &OAuthDevice, code_challenge: &str, trace_id: &str, port: u16) -> String {
    let mid = if device.machine_id.is_empty() {
        random_hex(32)
    } else {
        device.machine_id.clone()
    };
    let redirect_uri = format!("http://127.0.0.1:{port}/authorize");
    let mut q: Vec<(String, String)> = Vec::new();
    let mut set = |k: &str, v: String| q.push((k.to_string(), v));
    set("login_version", "1".into());
    set("auth_from", "trae".into());
    set("login_channel", "native_ide".into());
    set("plugin_version", OAUTH_PLUGIN_VERSION.into());
    set("auth_type", "local".into());
    set("client_id", OAUTH_CLIENT_ID.into());
    set("redirect", "0".into());
    set("login_trace_id", trace_id.into());
    set("auth_callback_url", redirect_uri);
    set("machine_id", mid.clone());
    set("device_id", device.device_id.clone());
    set("x_device_id", device.device_id.clone());
    set("x_machine_id", mid);
    set("x_device_brand", hostname());
    set("x_device_type", "windows".into());
    set("x_os_version", "Windows".into());
    set("x_env", String::new());
    set("x_app_version", device.app_version.clone());
    set("x_app_type", "stable".into());
    set("code_challenge", code_challenge.into());
    set("code_challenge_method", "S256".into());
    set("channel_name", "common".into());
    let qs = q
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{OAUTH_PAGE}?{qs}")
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 解析回调 URL。兼容三种形态：
///   - 主路径：authCodeInfo=<JSON>（+ userInfo / loginTraceID / host / userRegion）
///   - 老形态：refreshToken / accessToken / userId / userName / avatar 直传
///   - 标准授权码：code
pub fn parse_callback(callback_url: &str) -> Result<CallbackInfo, String> {
    let Some(q_idx) = callback_url.find('?') else {
        return Err("回调 URL 中缺少查询参数".into());
    };
    let query = &callback_url[q_idx + 1..];
    let mut params = std::collections::HashMap::new();
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else { continue };
        params.insert(percent_decode(k), percent_decode(v));
    }
    let get = |k: &str| params.get(k).cloned().unwrap_or_default();

    let mut out = CallbackInfo {
        auth_code: None,
        refresh_token: non_empty(&get("refreshToken")).or_else(|| non_empty(&get("refresh_token"))),
        access_token: non_empty(&get("accessToken")).or_else(|| non_empty(&get("access_token"))),
        user_id: non_empty(&get("userId"))
            .or_else(|| non_empty(&get("user_id")))
            .or_else(|| non_empty(&get("UserID"))),
        user_name: non_empty(&get("userName"))
            .or_else(|| non_empty(&get("user_name")))
            .or_else(|| non_empty(&get("nickname"))),
        avatar: non_empty(&get("avatar")),
        host: non_empty(&get("host")),
        user_region: non_empty(&get("userRegion")),
        login_trace_id: non_empty(&get("loginTraceID")).or_else(|| non_empty(&get("login_trace_id"))),
    };

    let raw_code = get("authCodeInfo");
    if !raw_code.is_empty() {
        let v: Value = serde_json::from_str(&raw_code)
            .map_err(|e| format!("authCodeInfo 解析失败（{e}）：授权页回调格式异常"))?;
        let code = v.get("AuthCode").and_then(|c| c.as_str()).map(String::from);
        let code = code.ok_or("authCodeInfo 中缺少 AuthCode 字段")?;
        out.auth_code = Some(code);
    }
    if out.auth_code.is_none() {
        out.auth_code = non_empty(&get("code"));
    }

    let raw_user = get("userInfo");
    if !raw_user.is_empty() {
        if let Ok(v) = serde_json::from_str::<Value>(&raw_user) {
            if out.user_id.is_none() {
                out.user_id = v.get("UserID").and_then(|x| x.as_str()).map(String::from);
            }
            if out.user_name.is_none() {
                out.user_name = v
                    .get("ScreenName")
                    .or_else(|| v.get("NickName"))
                    .and_then(|x| x.as_str())
                    .map(String::from);
            }
            if out.avatar.is_none() {
                out.avatar = v.get("AvatarUrl").and_then(|x| x.as_str()).map(String::from);
            }
        }
    }

    let err = non_empty(&get("error")).or_else(|| non_empty(&get("errorCode")));
    if let Some(e) = err {
        let msg = get("errorMessage");
        return Err(if msg.is_empty() {
            format!("授权页返回错误：{e}")
        } else {
            format!("授权页返回错误：{e} - {msg}")
        });
    }

    if out.auth_code.is_none() && out.refresh_token.is_none() {
        return Err("回调 URL 中缺少 authCodeInfo / refreshToken 参数".into());
    }
    Ok(out)
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if hi >= 0 && lo >= 0 {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> i32 {
    match b {
        b'0'..=b'9' => (b - b'0') as i32,
        b'a'..=b'f' => (b - b'a' + 10) as i32,
        b'A'..=b'F' => (b - b'A' + 10) as i32,
        _ => -1,
    }
}

#[derive(Debug, Clone, Default)]
pub struct CallbackInfo {
    pub auth_code: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub avatar: Option<String>,
    pub host: Option<String>,
    pub user_region: Option<String>,
    pub login_trace_id: Option<String>,
}

// ───────────────────────── AuthCode → Token ─────────────────────────

/// 复刻客户端的到期时间算法：TokenExpireAt 已过期但给了 TokenExpireDuration 时，
/// 按「当前时间 + duration」算，否则用 TokenExpireAt。
pub fn compute_expired_at(expire_at: Option<&str>, duration_ms: Option<&str>) -> Option<String> {
    let expire_at = expire_at?;
    let r = chrono::DateTime::parse_from_rfc3339(expire_at).ok()?.timestamp_millis();
    let now = now_ms();
    let d = duration_ms.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let t = if now > r && d > 0 { now + d } else { r };
    Some(
        chrono::DateTime::from_timestamp_millis(t)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| expire_at.to_string()),
    )
}

/// 响应里可能出现 token 的键名，**顺序即优先级**（大写 `Token` 必须排第一）。
pub const ACCESS_KEYS: [&str; 7] = ["Token", "AccessToken", "access_token", "accessToken", "token", "Jwt", "JWT"];
pub const REFRESH_KEYS: [&str; 3] = ["RefreshToken", "refresh_token", "refreshToken"];

/// 在 JSON 树里找「首个非空字符串值」：先按精确键名，再按**大小写不敏感**键名，最后递归。
fn find_token_value(v: &Value, keys: &[&str]) -> Option<String> {
    if v.is_null() {
        return None;
    }
    if let Some(arr) = v.as_array() {
        for x in arr {
            if let Some(hit) = find_token_value(x, keys) {
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
        for (k, val) in obj {
            if let Some(s) = val.as_str() {
                if !s.is_empty() && keys.iter().any(|want| want.eq_ignore_ascii_case(k)) {
                    return Some(s.to_string());
                }
            }
        }
        for val in obj.values() {
            if let Some(hit) = find_token_value(val, keys) {
                return Some(hit);
            }
        }
    }
    None
}

/// 深层打码（保留结构、值只留前 6 位）——用于把响应原样记进日志排错，又不把 token 落盘。
fn mask_deep(v: &Value, depth: usize) -> Value {
    if depth > 6 {
        return json!("[deep]");
    }
    if let Some(arr) = v.as_array() {
        return json!(arr.iter().take(3).map(|x| mask_deep(x, depth + 1)).collect::<Vec<_>>());
    }
    if let Some(obj) = v.as_object() {
        let mut out = serde_json::Map::new();
        for (k, val) in obj {
            let sensitive = ["token", "jwt", "secret", "password", "authcode", "credential", "verifier", "code"]
                .iter()
                .any(|s| k.to_lowercase().contains(s));
            if sensitive {
                if let Some(s) = val.as_str() {
                    if s.len() > 12 {
                        out.insert(k.clone(), json!(format!("{}…(len={})", &s[..6], s.len())));
                        continue;
                    }
                }
            }
            out.insert(k.clone(), mask_deep(val, depth + 1));
        }
        return json!(out);
    }
    v.clone()
}

/// 解析 ExchangeToken 的响应体 → token 字段。
fn parse_exchange_response(body: &Value, status: u16) -> Result<ExchangeResult, String> {
    let err_meta = body.get("ResponseMetadata").and_then(|m| m.get("Error"));
    if let Some(err) = err_meta {
        if let Some(code) = err.get("Code") {
            if code.as_i64().map(|c| c != 0).unwrap_or(false) || code.as_str().map(|s| s != "0").unwrap_or(false) {
                let std_code = err
                    .get("StandardCode")
                    .and_then(|s| s.as_str())
                    .map(|s| format!("/{s}"))
                    .unwrap_or_default();
                return Err(format!(
                    "ExchangeToken 失败（HTTP {status}）code={code}{std_code}: {}",
                    err.get("Message").and_then(|m| m.as_str()).unwrap_or("未知错误")
                ));
            }
        }
    }
    if let Some(c) = body.get("code").and_then(|c| c.as_i64()) {
        if c != 0 {
            return Err(format!(
                "ExchangeToken 失败（HTTP {status}）code={c}: {}",
                body.get("message").and_then(|m| m.as_str()).unwrap_or("未知错误")
            ));
        }
    }

    let scope = body
        .get("Result")
        .or_else(|| body.get("result"))
        .or_else(|| body.get("Data"))
        .or_else(|| body.get("data"))
        .unwrap_or(body);
    let mut token = find_token_value(scope, &ACCESS_KEYS);
    let mut refresh_token = find_token_value(scope, &REFRESH_KEYS);
    if token.is_none() {
        token = find_token_value(body, &ACCESS_KEYS);
    }
    if refresh_token.is_none() {
        refresh_token = find_token_value(body, &REFRESH_KEYS);
    }
    let (Some(token), Some(refresh_token)) = (token, refresh_token) else {
        let top_keys: Vec<&str> = body
            .as_object()
            .map(|o| o.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();
        let result_keys: Vec<&str> = body
            .get("Result")
            .and_then(|r| r.as_object())
            .map(|o| o.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();
        return Err(format!(
            "ExchangeToken 响应里找不到 Token 字段（HTTP {status}）：顶层键=[{}]、Result 键=[{}]",
            top_keys.join(","),
            result_keys.join(",")
        ));
    };

    let result = body.get("Result");
    let expired_at = result.and_then(|r| {
        let e = r.get("TokenExpireAt").and_then(|v| v.as_str());
        let d = r.get("TokenExpireDuration").and_then(|v| v.as_str());
        compute_expired_at(e, d)
    });
    let refresh_expired_at = result
        .and_then(|r| r.get("RefreshExpireAt").and_then(|v| v.as_str()))
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.to_rfc3339());
    Ok(ExchangeResult {
        token,
        refresh_token,
        expired_at,
        refresh_expired_at,
    })
}

#[derive(Debug, Clone)]
pub struct ExchangeResult {
    pub token: String,
    pub refresh_token: String,
    pub expired_at: Option<String>,
    pub refresh_expired_at: Option<String>,
}

/// 用 AuthCode 交换 token（请求契约以客户端 main.js 为准）。
pub async fn exchange_auth_code(
    auth_code: &str,
    verifier: &str,
    device: &OAuthDevice,
    host: Option<&str>,
) -> Result<ExchangeResult, String> {
    let base = host.unwrap_or(OAUTH_DEFAULT_HOST).trim_end_matches('/');
    let url = format!("{base}{OAUTH_EXCHANGE_PATH}");
    let payload = json!({
        "ClientID": OAUTH_CLIENT_ID,
        "AuthCode": auth_code,
        "CodeVerifier": verifier,
        "DeviceInfo": {
            "DeviceID": device.device_id,
            "MachineID": if device.machine_id.is_empty() { random_hex(32) } else { device.machine_id.clone() },
            "PlatformCode": OAUTH_PLATFORM_CODE,
            "DeviceType": "PC",
            "DeviceName": "",
            "DeviceModel": "",
            "ClientVersion": device.app_version,
            "DevicePublicKey": device.public_key_pem.clone().unwrap_or_default(),
            "DeviceBrand": "",
            "DeviceCPU": "",
            "OSInfo": "",
            "OSVersion": "",
        },
        "IDEVersion": device.app_version,
    });
    let mut headers = std::collections::HashMap::new();
    headers.insert("accept".into(), "*/*".into());
    headers.insert("x-device-id".into(), device.device_id.clone());
    headers.insert("x-app-id".into(), OAUTH_APP_ID.into());
    headers.insert("x-platform-code".into(), OAUTH_PLATFORM_CODE.into());
    headers.insert("x-cloudide-token".into(), String::new());

    let resp = crate::modules::config::http_request(&url, "POST", Some(payload), Some(&headers)).await;
    let status = 200u16;
    let parsed = parse_exchange_response(&resp, status).map_err(|e| {
        oauth_log(&format!("EXCHANGE FAIL url={url} err={e} body={}", serde_json::to_string(&mask_deep(&resp, 0)).unwrap_or_default()));
        e
    })?;
    oauth_log(&format!(
        "EXCHANGE-OK url={url} tokenLen={} refreshLen={} expiredAt={} refreshExpiredAt={}",
        parsed.token.len(),
        parsed.refresh_token.len(),
        parsed.expired_at.as_deref().unwrap_or("-"),
        parsed.refresh_expired_at.as_deref().unwrap_or("-")
    ));
    Ok(parsed)
}

// ───────────────────────── 凭证型账号落库 ─────────────────────────

/// 读取某账号的 oauth.json（凭证）。
pub fn read_oauth_account(client_key: &str, id: &str) -> Option<Value> {
    let p = account_dir(client_key, id).join("oauth.json");
    let text = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(&text).ok()
}

/// 该账号是否为「仅凭证」账号（网页登录得到，无登录态载体）。
pub fn is_oauth_only(client_key: &str, id: &str) -> bool {
    read_meta(client_key, id)
        .map(|m| m.kind == "oauth")
        .unwrap_or(false)
}

/// 账号库里所有账号的 uid → {id, kind} 索引（跨载体账号与凭证账号查重）。
pub fn vault_uid_index(client_key: &str) -> std::collections::HashMap<String, (String, String)> {
    let mut out = std::collections::HashMap::new();
    for id in list_vault_accounts(client_key) {
        if let Some(oa) = read_oauth_account(client_key, &id) {
            if let Some(uid) = oa.get("uid").and_then(|v| v.as_str()) {
                out.insert(uid.to_string(), (id, "oauth".into()));
                continue;
            }
        }
        let sp = account_dir(client_key, &id).join(REL_STORAGE);
        if let Ok(text) = std::fs::read_to_string(&sp) {
            if let Some(uid) = crate::modules::trae_vault::uid_from_storage_text(&text) {
                out.insert(uid, (id, "carrier".into()));
            }
        }
    }
    out
}

/// 落库一个凭证型账号（不写任何客户端登录态文件）。
#[allow(clippy::too_many_arguments)]
pub fn save_oauth_account(
    client_key: &str,
    uid: Option<&str>,
    name: Option<&str>,
    token: &str,
    refresh_token: &str,
    device: &OAuthDevice,
    user_name: Option<&str>,
    avatar: Option<&str>,
    host: Option<&str>,
    user_region: Option<&str>,
    expired_at: Option<&str>,
    refresh_expired_at: Option<&str>,
) -> Result<SavedAccount, String> {
    let base = sanitize_name(
        &name
            .filter(|n| !n.trim().is_empty())
            .map(|n| n.to_string())
            .unwrap_or_else(|| {
                uid.map(|u| format!("oauth_{}", &u[u.len().saturating_sub(6)..]))
                    .unwrap_or_else(|| format!("oauth_{}", random_hex(6)))
            }),
    );
    let mut id = base.clone();
    let uid_str = uid.map(|u| u.to_string());

    // 同 uid 已存在则原地更新（重新登录同一账号不该产生副本），但要标记 duplicate；
    // 若同 uid 是**载体账号**，则另建凭证账号，但把事实带出去。
    let twin = uid_str
        .as_deref()
        .and_then(|u| vault_uid_index(client_key).get(u).cloned());
    let existing_id = twin.as_ref().filter(|(_, kind)| kind == "oauth").map(|(id, _)| id.clone());
    let carrier_twin = twin.as_ref().filter(|(_, kind)| kind == "carrier").map(|(id, _)| id.clone());
    let duplicate = existing_id.is_some();
    if let Some(eid) = &existing_id {
        id = eid.clone();
    } else {
        let mut n = 1usize;
        while account_dir(client_key, &id).exists() {
            id = format!("{base}_{}", n + 1);
            n += 1;
        }
    }
    let prev = if duplicate {
        read_oauth_account(client_key, &id)
    } else {
        None
    };

    let display_name = name
        .filter(|n| !n.trim().is_empty())
        .map(String::from)
        .or_else(|| user_name.map(String::from))
        .unwrap_or_else(|| {
            uid.map(|u| format!("账号 {}", &u[u.len().saturating_sub(6)..]))
                .unwrap_or_else(|| id.clone())
        });
    let now = chrono::Local::now().to_rfc3339();
    let token_exp = expired_at
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp_millis())
        .or_else(|| Some(jwt_exp(token)))
        .unwrap_or(0);

    let payload = json!({
        "kind": "oauth",
        "id": id,
        "client": client_key,
        "displayName": display_name,
        "uid": uid_str,
        "userName": user_name,
        "avatar": avatar,
        "token": token,
        "refreshToken": refresh_token,
        "tokenExp": token_exp,
        "expiredAt": expired_at,
        "refreshExpiredAt": refresh_expired_at,
        "deviceId": device.device_id,
        "machineId": device.machine_id,
        "privateKeyPEM": device.private_key_pem,
        "publicKeyPEM": device.public_key_pem,
        "appVersion": device.app_version,
        "deviceSource": device.source,
        "host": host.unwrap_or(OAUTH_DEFAULT_HOST),
        "userRegion": user_region.map(|r| r.to_uppercase()).unwrap_or_else(|| "CN".into()),
        "loginSource": "oauth-web",
        "createdAt": prev.as_ref().and_then(|p| p.get("createdAt").and_then(|v| v.as_str())).unwrap_or(&now),
        "updatedAt": now,
    });

    let dir = account_dir(client_key, &id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建账号目录失败: {e}"))?;
    std::fs::write(
        dir.join("oauth.json"),
        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("写 oauth.json 失败: {e}"))?;
    let meta = json!({
        "id": id,
        "client": client_key,
        "kind": "oauth",
        "displayName": display_name,
        "entries": [],
        "files": [],
        "file_count": 0,
        "total_bytes": 0,
        "created_at": prev.as_ref().and_then(|p| p.get("createdAt").and_then(|v| v.as_str())).unwrap_or(&now),
        "note": "",
    });
    std::fs::write(
        dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("写 meta.json 失败: {e}"))?;

    Ok(SavedAccount {
        id,
        display_name,
        uid: uid_str,
        duplicate,
        carrier_twin,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct SavedAccount {
    pub id: String,
    pub display_name: String,
    pub uid: Option<String>,
    pub duplicate: bool,
    pub carrier_twin: Option<String>,
}

/// 把登录态里的时间字段（毫秒/秒数字 或 ISO 字符串）统一转 RFC3339。
fn ts_to_rfc3339(v: &Value) -> Option<String> {
    let ts = match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_u64().map(|x| x as i64))?,
        Value::String(s) => {
            if s.chars().any(|c| !c.is_ascii_digit()) {
                return Some(s.clone());
            }
            s.parse::<i64>().ok()?
        }
        _ => return None,
    };
    let ms = if ts < 1_000_000_000_000 { ts * 1000 } else { ts };
    chrono::DateTime::from_timestamp_millis(ms).map(|dt| dt.to_rfc3339())
}

/// 导入本地登录态：解密客户端 storage.json 的授权条目，落库为凭证账号（kind=oauth）。
/// 免浏览器登录流程，等价于网页登录得到的账号（可查额度 / 签到 / 用量）。
pub fn import_local_login(client_key: &str) -> Result<Value, String> {
    let client = get_client(client_key).ok_or("未知客户端")?;
    let text = std::fs::read_to_string(storage_json_path(client))
        .map_err(|_| "未找到该客户端的登录态文件（User/globalStorage/storage.json）".to_string())?;
    let storage: Value =
        serde_json::from_str(&text).map_err(|_| "登录态文件解析失败（非合法 JSON）".to_string())?;
    let obj = storage.as_object().ok_or("登录态文件格式异常")?;
    let enc = obj
        .get(KEY_AUTH)
        .and_then(|v| v.as_str())
        .ok_or("该客户端未登录（storage.json 中无授权信息）")?;
    if !is_km_value(enc) {
        return Err("授权信息格式异常（非 Km 加密条目）".into());
    }
    let auth = decrypt_km_json(enc).ok_or("登录态解密失败（可能客户端版本已变更加密方式）")?;
    let token = auth
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("解密结果中不含 token")?;
    if token.is_empty() {
        return Err("解密结果中 token 为空".into());
    }
    let refresh_token = auth.get("refreshToken").and_then(|v| v.as_str()).unwrap_or("");
    let uid = auth
        .get("userId")
        .map(|v| match v {
            Value::Number(n) => n.as_i64().map(|x| x.to_string()).or_else(|| n.as_u64().map(|x| x.to_string())),
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
        .flatten()
        .or_else(|| jwt_user_id(token));
    let user_name = auth.get("userName").and_then(|v| v.as_str()).map(String::from);
    let avatar = auth.get("avatar").and_then(|v| v.as_str()).map(String::from);
    let expired_at = auth.get("expiredAt").and_then(ts_to_rfc3339);
    let refresh_expired_at = auth.get("refreshExpiredAt").and_then(ts_to_rfc3339);

    // 设备身份：优先复用客户端 icube-dc 设备密钥；没有则用自建设备。
    let device = device_from_storage(&storage)
        .map(|mut d| {
            if d.machine_id.is_empty() {
                d.machine_id = random_hex(32);
            }
            d.source = format!("{client_key}（客户端设备密钥）");
            d
        })
        .unwrap_or_else(load_or_create_self_device);

    let saved = save_oauth_account(
        client_key,
        uid.as_deref(),
        None,
        token,
        refresh_token,
        &device,
        user_name.as_deref(),
        avatar.as_deref(),
        None,
        None,
        expired_at.as_deref(),
        refresh_expired_at.as_deref(),
    )?;
    Ok(json!({
        "ok": true,
        "id": saved.id,
        "uid": saved.uid,
        "displayName": saved.display_name,
        "duplicate": saved.duplicate,
        "carrierTwin": saved.carrier_twin,
        "source": "local-import",
        "client": client_key,
        "storageFile": storage_json_path(client).to_string_lossy(),
    }))
}

/// 一键导入：扫描全部已安装客户端，收集每个客户端的本地登录态。
/// 返回逐客户端结果（成功 / 未登录 / 失败原因），无登录态时也算成功（空结果）。
pub fn import_all_local_logins() -> Value {
    let mut results: Vec<Value> = Vec::new();
    for c in crate::modules::trae_discover::CLIENTS.iter() {
        let r = match import_local_login(c.key) {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "client": c.key, "error": e }),
        };
        results.push(r);
    }
    json!({ "results": results })
}

// ───────────────────────── 回环监听 ─────────────────────────

/// 进行中的登录会话（全局单例，前端 1.5s 轮询状态）。
#[derive(Debug, Clone, Serialize)]
pub struct OAuthSession {
    pub state: String,
    pub message: String,
    pub account: Option<String>,
    pub uid: Option<String>,
    pub duplicate: bool,
    pub carrier_twin: Option<String>,
    pub note: Option<String>,
    pub login_url: String,
    pub port: u16,
    pub fell_back: bool,
    pub started_at: i64,
    pub device_source: Option<String>,
    pub restored: bool,
}

struct Inner {
    pub session: OAuthSession,
    pub client_key: String,
    pub name: Option<String>,
    pub verifier: String,
    pub trace_id: String,
    pub device: OAuthDevice,
    /// 回调线程收到授权页跳回后暂存的完整回调 URL（交换由前端轮询驱动）。
    pub callback_url: Option<String>,
}

struct PendingLogin {
    client_key: String,
    name: Option<String>,
    verifier: String,
    trace_id: String,
    device: OAuthDevice,
    login_url: String,
    started_at: i64,
}

static LOOP: OnceLock<Mutex<Option<Inner>>> = OnceLock::new();

fn loop_guard() -> &'static Mutex<Option<Inner>> {
    LOOP.get_or_init(|| Mutex::new(None))
}

fn pending_path() -> PathBuf {
    store_dir().join("trae").join("oauth_pending.json")
}

fn write_pending(inner: &Inner) {
    let data = json!({
        "clientKey": inner.client_key,
        "name": inner.name,
        "verifier": inner.verifier,
        "traceId": inner.trace_id,
        "device": inner.device,
        "loginUrl": inner.session.login_url,
        "startedAt": inner.session.started_at,
    });
    let path = pending_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&data).unwrap_or_default());
}

fn read_pending() -> Option<PendingLogin> {
    let text = std::fs::read_to_string(pending_path()).ok()?;
    let j: Value = serde_json::from_str(&text).ok()?;
    let verifier = j.get("verifier")?.as_str()?.to_string();
    let device: OAuthDevice = serde_json::from_value(j.get("device")?.clone()).ok()?;
    if device.device_id.is_empty() {
        return None;
    }
    let started_at = j.get("startedAt").and_then(|v| v.as_i64()).unwrap_or(0);
    if now_ms() - started_at > PENDING_TTL_MS {
        return None;
    }
    Some(PendingLogin {
        client_key: j.get("clientKey").and_then(|v| v.as_str()).unwrap_or("solo-cn").to_string(),
        name: j.get("name").and_then(|v| v.as_str()).map(String::from),
        verifier,
        trace_id: j.get("traceId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        device,
        login_url: j.get("loginUrl").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        started_at,
    })
}

fn clear_pending() {
    let _ = std::fs::remove_file(pending_path());
}

/// 有没有「已落盘但本进程没在监听」的登录会话（服务重启后 / 弹层关掉后）。
pub fn pending_login() -> Option<Value> {
    if loop_guard().lock().unwrap().is_some() {
        return None;
    }
    let p = read_pending()?;
    Some(json!({
        "clientKey": p.client_key,
        "name": p.name,
        "loginUrl": p.login_url,
        "startedAt": p.started_at,
    }))
}

/// 取出回调线程暂存的本机回调 URL（只取一次；交换由调用方异步驱动）。
pub fn take_callback_url() -> Option<String> {
    let mut guard = loop_guard().lock().unwrap();
    guard.as_mut().and_then(|inner| inner.callback_url.take())
}

/// 当前回环监听状态（供前端轮询）。
pub fn oauth_status() -> Value {
    let guard = loop_guard().lock().unwrap();
    if let Some(inner) = guard.as_ref() {
        let s = &inner.session;
        return json!({
            "state": s.state,
            "message": s.message,
            "account": s.account,
            "uid": s.uid,
            "duplicate": s.duplicate,
            "carrierTwin": s.carrier_twin,
            "loginUrl": s.login_url,
            "port": s.port,
            "fellBack": s.fell_back,
            "startedAt": s.started_at,
            "deviceSource": s.device_source,
            "restored": s.restored,
            "pending": null,
        });
    }
    let pending = read_pending().map(|p| {
        json!({ "clientKey": p.client_key, "name": p.name, "loginUrl": p.login_url, "startedAt": p.started_at })
    });
    json!({ "state": "idle", "message": "", "pending": pending })
}

/// 停止回环监听（未启动时幂等）。同时清掉落盘的登录会话。
pub fn stop_loopback() {
    clear_pending();
    let mut guard = loop_guard().lock().unwrap();
    if let Some(mut inner) = guard.take() {
        inner.session.state = "stopped".into();
        inner.session.message = "已停止监听".into();
    }
}

/// 回环监听线程的存活期由全局状态驱动：waiting / callback_received / processing
/// 期间持续 accept；进入终态（done / error / stopped / 超时）后线程退出。
fn listener_thread(listener: TcpListener, session_id: i64) {
    listener.set_nonblocking(true).ok();
    let deadline = now_ms() + WAIT_TIMEOUT.as_millis() as i64;
    loop {
        let (state, is_final) = {
            let guard = loop_guard().lock().unwrap();
            match guard.as_ref() {
                Some(inner) => {
                    if inner.session.started_at != session_id {
                        return;
                    }
                    (inner.session.state.clone(), false)
                }
                None => return,
            }
        };
        // 等待超时：仅 waiting 态推进
        if state == "waiting" {
            let now = now_ms();
            let mut guard = loop_guard().lock().unwrap();
            if let Some(inner) = guard.as_mut() {
                if inner.session.started_at == session_id && inner.session.state == "waiting" && now >= deadline {
                    inner.session.state = "error".into();
                    inner.session.message = "等待授权超时（5 分钟），已停止监听".into();
                    clear_pending();
                    oauth_log("TIMEOUT 5 分钟内未收到回调，已停止监听");
                    return;
                }
            }
        }
        if is_final {
            return;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                handle_callback_conn(&mut stream, session_id);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(60));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(60));
            }
        }
    }
}

/// 处理一次回环连接：解析 HTTP 请求 → 暂存回调 URL → 返回中文结果页。
fn handle_callback_conn(stream: &mut TcpStream, session_id: i64) {
    let port = {
        let guard = loop_guard().lock().unwrap();
        match guard.as_ref() {
            Some(inner) if inner.session.started_at == session_id => inner.session.port,
            _ => OAUTH_LOOPBACK_PORT,
        }
    };
    let request = read_http_request(stream);
    let callback_url = request
        .split(' ')
        .nth(1)
        .map(|target| format!("http://127.0.0.1:{port}{target}"))
        .unwrap_or_default();
    let is_authorize = callback_url.contains("/authorize");
    let has_code = callback_url.contains("authCodeInfo=") || callback_url.contains("code=");

    if !is_authorize {
        let _ = write_http_response(stream, 404, "text/plain; charset=utf-8", b"404");
        return;
    }

    oauth_log(&format!(
        "CALLBACK 收到回调 authCode={has_code} url={}",
        &callback_url[..callback_url.len().min(160)]
    ));
    {
        let mut guard = loop_guard().lock().unwrap();
        if let Some(inner) = guard.as_mut() {
            if inner.session.started_at == session_id && matches!(inner.session.state.as_str(), "waiting" | "callback_received") {
                inner.session.state = "callback_received".into();
                inner.session.message = "已收到授权回调，正在完成登录…".into();
                inner.callback_url = Some(callback_url.clone());
            }
        }
    }
    let html = format!(
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>Trae 账号登录</title></head>\
         <body style=\"margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f6f7f9;font-family:system-ui,'Microsoft YaHei',sans-serif\">\
         <div style=\"background:#fff;border-radius:12px;padding:40px 48px;max-width:560px;box-shadow:0 4px 16px rgba(0,0,0,.08);text-align:center\">\
         <h1 style=\"font-size:20px;margin:0 0 12px;color:#111\">授权回调已收到</h1>\
         <p style=\"color:#555;line-height:1.7\">正在完成登录（换取令牌并写入账号库），请返回应用查看结果。此页面可以关闭。</p>\
         <p style=\"color:#94a3b8;font-size:12px;margin-top:18px\">本机回调监听端口 {port}</p></div></body></html>"
    );
    let _ = write_http_response(stream, 200, "text/html; charset=utf-8", html.as_bytes());
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn write_http_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// 起回环监听并返回登录 URL（不自动开浏览器，交给调用方决定）。
///
/// 端口策略：先抢 17388（与 Trae IDE 默认回调端口一致）；若被占用就**降级到系统随机端口**。
pub fn start_loopback(client_key: &str, name: Option<&str>) -> Result<Value, String> {
    stop_loopback();
    if get_client(client_key).is_none() {
        return Err(format!("未知客户端：{client_key}"));
    }
    let device = resolve_oauth_device(Some(client_key))?;
    let (verifier, challenge) = pkce_pair();
    let trace_id = random_hex(32);

    let (listener, port, fell_back) = match TcpListener::bind(("127.0.0.1", OAUTH_LOOPBACK_PORT)) {
        Ok(l) => (l, OAUTH_LOOPBACK_PORT, false),
        Err(_) => match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => {
                let p = l.local_addr().map(|a| a.port()).unwrap_or(0);
                (l, p, true)
            }
            Err(e) => return Err(format!("回环监听启动失败：{e}")),
        },
    };
    let login_url = build_login_url(&device, &challenge, &trace_id, port);
    let started_at = now_ms();
    let session = OAuthSession {
        state: "waiting".into(),
        message: if fell_back {
            format!("等待浏览器完成授权…（{OAUTH_LOOPBACK_PORT} 被占用，本次改用端口 {port}）")
        } else {
            "等待浏览器完成授权…".into()
        },
        account: None,
        uid: None,
        duplicate: false,
        carrier_twin: None,
        note: None,
        login_url: login_url.clone(),
        port,
        fell_back,
        started_at,
        device_source: Some(device.source.clone()),
        restored: false,
    };
    let trace_short = trace_id[..trace_id.len().min(8)].to_string();
    let inner = Inner {
        session,
        client_key: client_key.to_string(),
        name: name.map(String::from),
        verifier,
        trace_id,
        device: device.clone(),
        callback_url: None,
    };
    write_pending(&inner);
    *loop_guard().lock().unwrap() = Some(inner);

    let thread_id = started_at;
    let _t = std::thread::Builder::new()
        .name("trae-oauth-loopback".into())
        .spawn(move || listener_thread(listener, thread_id));

    oauth_log(&format!(
        "START client={client_key} trace={trace_short} port={port}{} device={} name={}",
        if fell_back { format!("(降级自 {OAUTH_LOOPBACK_PORT})") } else { String::new() },
        device.source,
        name.unwrap_or("-")
    ));
    Ok(json!({
        "loginUrl": login_url,
        "port": port,
        "fellBack": fell_back,
        "deviceSource": device.source,
    }))
}

// ───────────────────────── 登录收尾（交换 + 落库） ─────────────────────────

/// 核心收尾：解析回调 → 换 token → 落库。回环监听与手动粘贴两条路径共用。
pub async fn complete_login_from_callback(callback_url: &str, override_key: Option<&str>, override_name: Option<&str>) -> Value {
    let mut restored = false;
    {
        let mut guard = loop_guard().lock().unwrap();
        if guard.is_none() {
            if let Some(p) = read_pending() {
                let session = OAuthSession {
                    state: "waiting".into(),
                    message: "（从上次未完成的登录会话恢复）".into(),
                    account: None,
                    uid: None,
                    duplicate: false,
                    carrier_twin: None,
                    note: None,
                    login_url: p.login_url,
                    port: OAUTH_LOOPBACK_PORT,
                    fell_back: false,
                    started_at: p.started_at,
                    device_source: Some(p.device.source.clone()),
                    restored: true,
                };
                *guard = Some(Inner {
                    session,
                    client_key: p.client_key,
                    name: p.name,
                    verifier: p.verifier,
                    trace_id: p.trace_id,
                    device: p.device,
                    callback_url: None,
                });
                restored = true;
            }
        }
    }

    let (client_key, name, expected_trace, verifier, device) = {
        let guard = loop_guard().lock().unwrap();
        match guard.as_ref() {
            Some(inner) => (
                override_key.unwrap_or(&inner.client_key).to_string(),
                override_name.or(inner.name.as_deref()).map(String::from),
                inner.trace_id.clone(),
                inner.verifier.clone(),
                inner.device.clone(),
            ),
            None => (
                override_key.unwrap_or("solo-cn").to_string(),
                override_name.map(String::from),
                String::new(),
                String::new(),
                OAuthDevice {
                    device_id: String::new(),
                    machine_id: String::new(),
                    private_key_pem: None,
                    public_key_pem: None,
                    app_version: OAUTH_APP_VERSION.into(),
                    source: String::new(),
                },
            ),
        }
    };

    // 阻止并发：把回调会话标记为 processing（幂等），其余轮询直接返回当前状态。
    {
        let mut guard = loop_guard().lock().unwrap();
        if let Some(inner) = guard.as_mut() {
            if inner.session.state == "callback_received" || (inner.session.state == "waiting" && inner.callback_url.is_some()) {
                inner.session.state = "processing".into();
                inner.session.message = "正在完成登录…".into();
            }
        }
    }

    let cb = match parse_callback(callback_url) {
        Ok(cb) => cb,
        Err(e) => {
            return fail(&format!("{e}"));
        }
    };

    // CSRF：签发的 login_trace_id 会被授权页原样回传为 loginTraceID
    if !expected_trace.is_empty() {
        if let Some(got) = &cb.login_trace_id {
            if got != &expected_trace {
                return fail("loginTraceID 校验失败：回调与本机发起的登录请求不匹配（可能被伪造或重放）");
            }
        }
    }

    let mut token = cb.access_token.clone();
    let mut refresh_token = cb.refresh_token.clone();
    let mut expired_at = None;
    let mut refresh_expired_at = None;

    if let Some(auth_code) = &cb.auth_code {
        if verifier.is_empty() {
            return fail("本机没有对应的 PKCE verifier，无法完成 AuthCode 交换（请从本工具重新发起登录）");
        }
        match exchange_auth_code(auth_code, &verifier, &device, cb.host.as_deref()).await {
            Ok(r) => {
                token = Some(r.token);
                refresh_token = Some(r.refresh_token);
                expired_at = r.expired_at;
                refresh_expired_at = r.refresh_expired_at;
            }
            Err(e) => return fail(&e),
        }
    }
    let (Some(token), Some(refresh_token)) = (token, refresh_token) else {
        return fail("回调未提供可用的 token（缺少 accessToken 或 refreshToken）");
    };

    let uid = cb.user_id.clone().or_else(|| jwt_user_id(&token));
    let saved = match save_oauth_account(
        &client_key,
        uid.as_deref(),
        name.as_deref(),
        &token,
        &refresh_token,
        &device,
        cb.user_name.as_deref(),
        cb.avatar.as_deref(),
        cb.host.as_deref(),
        cb.user_region.as_deref(),
        expired_at.as_deref(),
        refresh_expired_at.as_deref(),
    ) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };

    let (message, note): (String, Option<String>) = if saved.duplicate {
        (
            format!(
                "这次拿到的还是已有账号 [{}]（= 浏览器里当前登录的 Trae 账号）。若要添加另一个账号，请改用「无痕窗口打开」重新登录。",
                saved.display_name
            ),
            Some("要登录另一个账号？网页授权用的是浏览器当前的 Trae 登录态，所以又取回了同一个账号。任选一种方式：① 点「无痕窗口打开」（推荐）；② 先在浏览器里退出 Trae 登录，再重新发起。".into()),
        )
    } else if let Some(twin) = &saved.carrier_twin {
        (
            format!(
                "网页凭证已保存到账号 [{}]。注意：该账号在本机已存在可切换的载体账号 [{}]，所以列表里会出现两条。",
                saved.display_name, twin
            ),
            Some(format!(
                "这不是一个新账号：本次登录的账号与已有的载体账号「{twin}」是同一个 Trae 账号。列表里因此有两张卡：一张能切换（客户端登录态），一张只能查额度/用量/签到（网页凭证）。"
            )),
        )
    } else {
        (format!("账号 [{}] 登录成功", saved.display_name), None)
    };

    {
        let mut guard = loop_guard().lock().unwrap();
        if let Some(inner) = guard.as_mut() {
            inner.session.state = "done".into();
            inner.session.account = Some(saved.id.clone());
            inner.session.uid = saved.uid.clone();
            inner.session.duplicate = saved.duplicate;
            inner.session.carrier_twin = saved.carrier_twin.clone();
            inner.session.message = message.clone();
            inner.session.note = note.clone();
            inner.callback_url = None;
        }
    }
    clear_pending();
    oauth_log(&format!("RESULT OK duplicate={} twin={} msg={message}", saved.duplicate, saved.carrier_twin.as_deref().unwrap_or("-")));

    // 登录成功仅此处拉取一次账号资料（GetUserInfo 真实昵称 + 积分余额）：
    // 之后不再自动访问接口，避免风控，仅能由前端「刷新积分」按钮手动触发。
    if let Some(oauth) = read_oauth_account(&client_key, &saved.id) {
        let _ = crate::modules::trae_profile::refresh_profile(&client_key, &saved.id, &oauth).await;
    }

    json!({
        "state": "done",
        "ok": true,
        "duplicate": saved.duplicate,
        "carrierTwin": saved.carrier_twin,
        "message": message,
        "note": note,
        "id": saved.id,
        "uid": saved.uid,
        "restored": restored,
    })
}

fn fail(msg: &str) -> Value {
    {
        let mut guard = loop_guard().lock().unwrap();
        if let Some(inner) = guard.as_mut() {
            inner.session.state = "error".into();
            inner.session.message = msg.to_string();
            inner.callback_url = None;
        }
    }
    oauth_log(&format!("RESULT FAIL msg={msg}"));
    json!({ "state": "error", "ok": false, "message": msg })
}

/// 手动粘贴回调 URL 兜底（不依赖回环监听）。
pub async fn complete_manual(client_key: &str, name: Option<&str>, callback_url: &str) -> Value {
    oauth_log(&format!(
        "MANUAL 手动提交回调 client={} url={}",
        client_key,
        &callback_url[..callback_url.len().min(160)]
    ));
    let r = complete_login_from_callback(callback_url, Some(client_key), name).await;
    r
}

// 浏览器探测与打开（私密窗口用）——供命令层复用，不依赖 Tauri。

#[derive(Debug, Clone, Serialize)]
pub struct BrowserInfo {
    pub key: &'static str,
    pub label: &'static str,
}

#[derive(Debug, Clone)]
struct BrowserExe {
    key: &'static str,
    label: &'static str,
    private_args: &'static [&'static str],
    rels: &'static [&'static str],
}

static BROWSER_DEFS: [BrowserExe; 5] = [
    BrowserExe {
        key: "edge",
        label: "Microsoft Edge",
        private_args: &["-inprivate"],
        rels: &["Microsoft/Edge/Application/msedge.exe"],
    },
    BrowserExe {
        key: "chrome",
        label: "Google Chrome",
        private_args: &["--incognito"],
        rels: &["Google/Chrome/Application/chrome.exe"],
    },
    BrowserExe {
        key: "brave",
        label: "Brave",
        private_args: &["--incognito"],
        rels: &["BraveSoftware/Brave-Browser/Application/brave.exe"],
    },
    BrowserExe {
        key: "firefox",
        label: "Mozilla Firefox",
        private_args: &["-private-window"],
        rels: &["Mozilla Firefox/firefox.exe"],
    },
    BrowserExe {
        key: "360",
        label: "360 极速浏览器",
        private_args: &["--incognito"],
        rels: &["360Chrome/Chrome/Application/360chrome.exe"],
    },
];

/// 检测本机可用的浏览器（私密窗口用）。返回 [(key, label, exe)]。
pub fn detect_browsers() -> Vec<BrowserInfo> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA"] {
        if let Ok(v) = std::env::var(var) {
            let p = PathBuf::from(v);
            if !roots.contains(&p) {
                roots.push(p);
            }
        }
    }
    roots.push(PathBuf::from("C:/Program Files"));
    roots.push(PathBuf::from("C:/Program Files (x86)"));
    if let Ok(ud) = std::env::var("USERNAME") {
        roots.push(PathBuf::from(format!("C:/Users/{ud}/AppData/Local")));
    }
    let mut out: Vec<BrowserInfo> = Vec::new();
    for def in BROWSER_DEFS.iter() {
        'rel: for rel in def.rels {
            for root in &roots {
                let p = root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
                if p.is_file() {
                    out.push(BrowserInfo {
                        key: def.key,
                        label: def.label,
                    });
                    break 'rel;
                }
            }
        }
    }
    out
}

fn resolve_browser_exe(key: &str) -> Option<(PathBuf, &'static [&'static str])> {
    let def = BROWSER_DEFS.iter().find(|d| d.key == key)?;
    let mut roots: Vec<PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA"] {
        if let Ok(v) = std::env::var(var) {
            let p = PathBuf::from(v);
            if !roots.contains(&p) {
                roots.push(p);
            }
        }
    }
    roots.push(PathBuf::from("C:/Program Files"));
    roots.push(PathBuf::from("C:/Program Files (x86)"));
    for rel in def.rels {
        for root in &roots {
            let p = root.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
            if p.is_file() {
                return Some((p, def.private_args));
            }
        }
    }
    None
}

fn is_safe_url(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://"))
        && !url.chars().any(|c| matches!(c, '"' | '\'' | '\r' | '\n'))
        && !url.chars().any(|c| (c as u32) < 0x20)
}

/// 用指定浏览器的私密窗口打开 URL（绕过 shell，`&` 天然安全）。
pub fn open_private(url: &str, browser_key: Option<&str>) -> Result<BrowserInfo, String> {
    if !is_safe_url(url) {
        return Err("URL 不合法（仅支持 http/https，且不含引号或换行）".into());
    }
    let list = detect_browsers();
    if list.is_empty() {
        return Err("未检测到可用的浏览器，请手动复制链接到无痕窗口打开".into());
    }
    let picked = if let Some(key) = browser_key {
        list.iter().find(|b| b.key == key).ok_or_else(|| format!("未安装浏览器：{key}"))?
    } else {
        &list[0]
    };
    let (exe, private_args) = resolve_browser_exe(picked.key).ok_or("浏览器探测失败")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(private_args);
    cmd.arg(url);
    cmd.spawn().map_err(|e| format!("打开浏览器失败：{e}"))?;
    let info = BrowserInfo {
        key: picked.key,
        label: picked.label,
    };
    Ok(info)
}

/// 用系统默认浏览器打开 URL。
/// Windows 下不能用 `cmd /c start`（URL 含 `&` 会被拆成多条命令）也不能用
/// explorer.exe（部分系统会误开文档管理器）。用 ShellExecuteW 才是标准做法。
pub fn open_in_browser(url: &str) -> Result<(), String> {
    if !is_safe_url(url) {
        return Err("URL 不合法（仅支持 http/https，且不含引号或换行）".into());
    }
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let url_w: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
        let op: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
        let res = unsafe {
            ShellExecuteW(
                HWND::default(),
                PCWSTR::from_raw(op.as_ptr()),
                PCWSTR::from_raw(url_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if (res.0 as isize) <= 32 {
            return Err(format!("打开浏览器失败：ShellExecute error {}", res.0 as isize));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let program = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
        std::process::Command::new(program)
            .arg(url)
            .spawn()
            .map_err(|e| format!("打开浏览器失败：{e}"))?;
        Ok(())
    }
}
