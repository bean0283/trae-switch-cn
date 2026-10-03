//! 载体合成（移植自 trae-switch src/synth.js）。
//!
//! 把「只有账号凭证、没有客户端登录态」的凭证账号（kind=oauth），变成能冷切换的
//! 一等公民：以当前 live 载体为骨架克隆，只重写三个身份键（iCubeAuthInfo://
//! icube.cloudide / usertag / icube-dc:<deviceId>），并抹掉上一账号的本地权益快照
//! （iCubeServerData://icube.cloudide），落进 vault 后走既有冷切换流程。
//!
//! 三个值都是 Km 密文，Km 加密算法硬编码、与机器无关（见 trae_km），因此可以
//! 自己造出客户端认得的登录态。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::modules::trae_carriers::{overwrite_entry, sanitize_entries};
use crate::modules::trae_discover::get_client;
use crate::modules::trae_km::{decrypt_km_json, encrypt_km_json, is_km_value, jwt_payload};
use crate::modules::trae_oauth::read_oauth_account;
use crate::modules::trae_vault::{backup, meta_path, read_meta, REL_STORAGE};

const KEY_AUTH: &str = "iCubeAuthInfo://icube.cloudide";
const KEY_TAG: &str = "iCubeAuthInfo://usertag";
const KEY_SERVER: &str = "iCubeServerData://icube.cloudide";
const PREFIX_DC: &str = "iCubeAuthInfo://icube-dc:";

fn read_json_safe(p: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(p).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    if v.is_object() {
        Some(v)
    } else {
        None
    }
}

fn make_tmp_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 拼出客户端 `iCubeAuthInfo://icube.cloudide` 里的账号本体。
/// 字段名与真实登录态对齐；`account` 以 live 里的既有结构为底，只覆盖身份字段，
/// 并抹掉上一位账号的隐私信息（邮箱/组织/手机号等），避免串号。
fn build_auth_record(oauth: &Value, donor_auth: Option<&Value>, host: &str) -> Value {
    let region = oauth
        .get("userRegion")
        .and_then(|v| v.as_str())
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| "CN".into());
    let tag = region.to_lowercase();
    let iat = oauth
        .get("token")
        .and_then(|t| t.as_str())
        .and_then(jwt_payload)
        .and_then(|p| p.get("iat").and_then(|v| v.as_i64()));
    let token_release = iat
        .and_then(|i| chrono::DateTime::from_timestamp(i, 0).map(|dt| dt.to_rfc3339()))
        .unwrap_or_else(|| chrono::Local::now().to_rfc3339());

    let mut account = donor_auth
        .and_then(|d| d.get("account"))
        .filter(|a| a.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Some(obj) = account.as_object_mut() {
        for k in [
            "email",
            "organization",
            "nonPlainTextMobile",
            "description",
            "work_country",
            "iss",
        ] {
            obj.insert(k.into(), Value::String(String::new()));
        }
        obj.insert("iat".into(), json!(0));
        obj.insert(
            "username".into(),
            json!(oauth
                .get("userName")
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| oauth.get("displayName").and_then(|v| v.as_str()).map(String::from))
                .unwrap_or_default()),
        );
        obj.insert(
            "avatar_url".into(),
            json!(oauth
                .get("avatar")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default()),
        );
        obj.insert("userTag".into(), json!(tag));
        if !obj.contains_key("storeRegion") {
            obj.insert("storeRegion".into(), json!(region));
        }
        if !obj.contains_key("scope") {
            obj.insert("scope".into(), json!("marscode"));
        }
        if !obj.contains_key("loginScope") {
            obj.insert("loginScope".into(), json!("trae"));
        }
        if !obj.get("migrateToSG").map(|v| v.is_boolean()).unwrap_or(false) {
            obj.insert("migrateToSG".into(), json!(false));
        }
        for k in ["storeCountryCode", "storeCountrySrc"] {
            if !obj.contains_key(k) {
                obj.insert(k.into(), Value::String(String::new()));
            }
        }
    }

    let expired_at = oauth
        .get("expiredAt")
        .and_then(|v| v.as_str())
        .map(|s| json!(s))
        .unwrap_or_else(|| {
            oauth
                .get("tokenExp")
                .and_then(|v| v.as_i64())
                .and_then(|ms| chrono::DateTime::from_timestamp_millis(ms))
                .map(|dt| json!(dt.to_rfc3339()))
                .unwrap_or(Value::Null)
        });

    json!({
        "token": oauth.get("token").unwrap_or(&Value::Null),
        "refreshToken": oauth.get("refreshToken").unwrap_or(&Value::Null),
        "expiredAt": expired_at,
        "refreshExpiredAt": oauth.get("refreshExpiredAt").and_then(|v| v.as_str()).map(|s| json!(s)).unwrap_or(Value::Null),
        "tokenReleaseAt": json!(token_release),
        "userId": json!(oauth.get("uid").and_then(|v| v.as_str()).map(String::from).unwrap_or_default()),
        "host": json!(host),
        "userRegion": json!({ "region": region, "_aiRegion": region }),
        "account": account,
    })
}

/// 该账号是否需要（重新）合成载体：是凭证账号（有 oauth.json），且还没有 storage.json 载体。
pub fn needs_synthesis(client_key: &str, id: &str) -> bool {
    if read_oauth_account(client_key, id).is_none() {
        return false;
    }
    !read_meta(client_key, id)
        .map(|m| m.files.iter().any(|f| f.rel.replace('\\', "/") == REL_STORAGE))
        .unwrap_or(false)
}

/// 用当前 live 载体合成一份属于该凭证账号的登录态，并写进 vault。
pub fn synthesize_carrier(
    client_key: &str,
    id: &str,
    root_dir: &Path,
    entries: &[String],
    on_log: Option<&dyn Fn(&str)>,
) -> Result<Value, String> {
    let oauth = read_oauth_account(client_key, id).ok_or_else(|| {
        "该账号不是「网页登录」得到的凭证账号（缺少 oauth.json），无法合成载体".to_string()
    })?;
    let uid = oauth
        .get("uid")
        .and_then(|v| {
            v.as_str()
                .map(String::from)
                .or_else(|| v.as_i64().map(|i| i.to_string()))
        })
        .ok_or("凭证账号缺少 uid，无法合成载体")?;
    let token = oauth.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let refresh_token = oauth.get("refreshToken").and_then(|v| v.as_str()).unwrap_or("");
    if token.is_empty() || refresh_token.is_empty() {
        return Err("凭证账号缺少 token / refreshToken，无法合成载体（请重新网页登录）".into());
    }
    let priv_pem = oauth
        .get("privateKeyPEM")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pub_pem = oauth
        .get("publicKeyPEM")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if priv_pem.is_empty() || pub_pem.is_empty() {
        return Err("凭证账号缺少设备密钥对，客户端无法续期 token，无法合成载体（请重新网页登录）".into());
    }
    let device_id = oauth
        .get("deviceId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let client = get_client(client_key).ok_or("未知客户端")?;
    let tmp = make_tmp_dir("trae-switch-synth");
    let result = (|| -> Result<Value, String> {
        // 1) 以当前 live 为载体骨架整树克隆（全局状态条目一律剔除，与切换同闸）
        let mut rels = sanitize_entries(entries);
        let rel_storage = REL_STORAGE.to_string();
        if !rels.iter().any(|r| *r == rel_storage) {
            rels.push(rel_storage);
        }
        for rel in &rels {
            if !root_dir.join(rel.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str())).exists() {
                continue;
            }
            overwrite_entry(root_dir, &tmp, rel);
        }

        // 2) 重写身份键
        let sp = tmp.join(REL_STORAGE.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        let mut storage = read_json_safe(&sp)
            .ok_or_else(|| "合成失败：live 骨架里没有 storage.json，请先在该客户端登录一次".to_string())?;

        let donor_raw = storage.get(KEY_AUTH).and_then(|v| v.as_str());
        let donor_auth = donor_raw.and_then(|r| if is_km_value(r) { decrypt_km_json(r) } else { None });
        let host = donor_auth
            .as_ref()
            .and_then(|d| d.get("host").and_then(|v| v.as_str()))
            .map(String::from)
            .or_else(|| oauth.get("host").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_else(|| client.api_host.to_string());
        let auth = build_auth_record(&oauth, donor_auth.as_ref(), &host);

        let tag_raw = storage.get(KEY_TAG).and_then(|v| v.as_str());
        let mut tag_map = tag_raw
            .and_then(|r| if is_km_value(r) { decrypt_km_json(r) } else { None })
            .filter(|v| v.is_object())
            .unwrap_or_else(|| json!({}));
        let tag = oauth
            .get("userRegion")
            .and_then(|v| v.as_str())
            .unwrap_or("CN")
            .to_lowercase();
        if tag_map.get(&uid).is_none() {
            if let Some(m) = tag_map.as_object_mut() {
                m.insert(uid.clone(), json!(tag));
            }
        }

        let dc_key = format!("{PREFIX_DC}{device_id}");
        if let Some(obj) = storage.as_object_mut() {
            obj.insert(
                KEY_AUTH.into(),
                json!(encrypt_km_json(&auth).map_err(|e| format!("加密账号本体失败：{e}"))?),
            );
            obj.insert(
                KEY_TAG.into(),
                json!(encrypt_km_json(&tag_map).map_err(|e| format!("加密用户标签失败：{e}"))?),
            );
            obj.insert(
                dc_key.clone(),
                json!(encrypt_km_json(&json!({
                    "privateKeyPEM": priv_pem,
                    "publicKeyPEM": pub_pem,
                }))
                .map_err(|e| format!("加密设备密钥失败：{e}"))?),
            );
            let dropped_server = obj.remove(KEY_SERVER).is_some();
            let _ = dropped_server;
        }

        std::fs::create_dir_all(sp.parent().unwrap_or(Path::new(".")))
            .map_err(|e| format!("创建骨架目录失败：{e}"))?;
        std::fs::write(&sp, serde_json::to_string_pretty(&storage).map_err(|e| e.to_string())?)
            .map_err(|e| format!("写骨架 storage.json 失败：{e}"))?;

        // 3) 落库（复用 vault.backup），并把 meta 改回真实 live 目录 + oauth 身份
        let captured: Vec<String> = rels
            .iter()
            .filter(|r| tmp.join(r.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str())).exists())
            .cloned()
            .collect();
        let m = backup(client_key, id, &tmp, &captured)?;
        let prev_meta = read_meta(client_key, id).unwrap_or_else(|| {
            crate::modules::trae_vault::VaultMeta {
                id: id.to_string(),
                client: client_key.to_string(),
                kind: "oauth".into(),
                root_dir: String::new(),
                entries: vec![],
                files: vec![],
                file_count: 0,
                total_bytes: 0,
                created_at: String::new(),
                last_used_at: None,
                verified_uid: None,
            }
        });
        let mut meta = serde_json::to_value(&m).map_err(|e| e.to_string())?;
        if let Some(obj) = meta.as_object_mut() {
            obj.insert("kind".into(), json!("oauth"));
            obj.insert("root_dir".into(), json!(root_dir.to_string_lossy().into_owned()));
            obj.insert(
                "display_name".into(),
                json!(oauth
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_default()),
            );
            obj.insert(
                "carrier".into(),
                json!({
                    "synthesized": true,
                    "synthesized_at": chrono::Local::now().to_rfc3339(),
                    "base": root_dir.to_string_lossy().into_owned(),
                    "host": host,
                    "uid": uid,
                    "device_id": device_id,
                    "skipped": [],
                }),
            );
            // 保留既有建档时间（backup 会重新盖一个「现在」的时间戳）
            if !prev_meta.created_at.is_empty() {
                obj.insert("created_at".into(), json!(prev_meta.created_at));
            }
        }
        std::fs::write(
            meta_path(client_key, id),
            serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("写 meta 失败：{e}"))?;

        if let Some(log) = on_log {
            log(&format!(
                "载体合成完成：以 {:?} 为骨架，重写 {KEY_AUTH} / {KEY_TAG} / {dc_key}（uid={uid}、host={host}）",
                root_dir
            ));
        }
        Ok(json!({
            "entries": captured,
            "keys": [KEY_AUTH, KEY_TAG, dc_key],
            "host": host,
            "uid": uid,
            "device_id": device_id,
            "file_count": m.file_count,
            "account_dir": account_dir_path(client_key, id),
        }))
    })();

    let _ = std::fs::remove_dir_all(&tmp);
    result
}

fn account_dir_path(client_key: &str, id: &str) -> String {
    crate::modules::trae_vault::account_dir(client_key, id)
        .to_string_lossy()
        .into_owned()
}
