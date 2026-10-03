//! 常量、路径与通用工具函数

use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// 官网套餐页桌面 Chrome UA（plans-usage 捕获）。
pub const DEFAULT_HTTP_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

// ---------------------------------------------------------------------------
// 路径
// ---------------------------------------------------------------------------

/// 覆盖家目录的环境变量名。
///
/// 设置后 `home_dir()` 返回它的值，于是 `~/.trae-switch-cn`、`~/.codebuddy`、
/// `~/.codebuddy-rotate` 全部落在指定目录下。用途：
/// - 集成测试把家目录沙箱化，避免读写真实账号与 CLI 配置；
/// - 自定义部署位置。
///
/// 未设置时行为与之前完全一致（`dirs::home_dir()`）。
pub const HOME_ENV_VAR: &str = "TRAE_SWITCH_HOME";

pub fn home_dir() -> PathBuf {
    if let Some(overridden) = std::env::var_os(HOME_ENV_VAR) {
        if !overridden.is_empty() {
            return PathBuf::from(overridden);
        }
    }
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub fn store_dir() -> PathBuf {
    home_dir().join(".trae-switch-cn")
}

// ---------------------------------------------------------------------------
// 时间
// ---------------------------------------------------------------------------

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 文件
// ---------------------------------------------------------------------------

/// 原子写文件（临时文件 + rename）。
pub fn atomic_write(path: &Path, content: &str) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!("{file_name}.tmp-{}", uuid::Uuid::new_v4().simple()));
    if let Err(e) = std::fs::write(&tmp, content) {
        eprintln!("[atomic] write tmp FAILED: {e}");
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        eprintln!("[atomic] rename FAILED: {e}");
        // rename 失败时清理临时文件，避免在目标目录残留 `<name>.tmp-*`。
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP 客户端
// ---------------------------------------------------------------------------

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(DEFAULT_HTTP_USER_AGENT)
}

fn http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        http_client_builder()
            .build()
            .expect("failed to build reqwest client")
    })
}

/// 通用 HTTP 请求，返回解析后的 JSON。
///
/// 行为对齐 Python 版：
/// - 2xx：解析 body 为 JSON；
/// - HTTP 错误：body 可解析则返回其 JSON，否则 `{"code": <status>, "message": <body 前 500 字符>}`；
/// - 网络错误：`{"code": -1, "message": <原因>}`。
pub async fn http_request(
    url: &str,
    method: &str,
    body: Option<Value>,
    headers: Option<&HashMap<String, String>>,
) -> Value {
    http_request_with_proxy(url, method, body, headers, None).await
}

/// 通用 HTTP 请求，可为单次请求显式指定 HTTP/HTTPS 代理。
pub async fn http_request_with_proxy(
    url: &str,
    method: &str,
    body: Option<Value>,
    headers: Option<&HashMap<String, String>>,
    proxy: Option<&str>,
) -> Value {
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let client = match proxy.map(str::trim).filter(|value| !value.is_empty()) {
        Some(proxy) => match http_client_builder()
            .proxy(match reqwest::Proxy::all(proxy) {
                Ok(proxy) => proxy,
                Err(e) => return json!({"code": -1, "message": format!("代理地址无效: {e}")}),
            })
            .build()
        {
            Ok(client) => client,
            Err(e) => return json!({"code": -1, "message": format!("代理客户端创建失败: {e}")}),
        },
        None => http_client().clone(),
    };
    let mut req = client.request(method, url);
    req = req.header("Content-Type", "application/json");
    if let Some(h) = headers {
        for (k, v) in h {
            req = req.header(k, v);
        }
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                serde_json::from_str(&text).unwrap_or(Value::Null)
            } else {
                serde_json::from_str(&text).unwrap_or_else(|_| {
                    json!({
                        "code": status.as_u16(),
                        "message": normalize_error_body(&text),
                    })
                })
            }
        }
        Err(e) => json!({"code": -1, "message": e.to_string()}),
    }
}

/// 非 JSON 错误响应体归一化：网关（openresty / APISIX 等）的 401/5xx 常返回
/// 整页 HTML，原样截断会把 `<html>…` 整段塞进通知与界面卡片（issue #94）。
/// HTML 提取 `<title>` 作为可读信息；其余保持原有的 500 字符截断。
fn normalize_error_body(text: &str) -> String {
    if text.trim_start().starts_with('<') {
        let title = text
            .split_once("<title>")
            .and_then(|(_, rest)| rest.split_once("</title>"))
            .map(|(title, _)| title.trim())
            .unwrap_or_default();
        return if title.is_empty() {
            "服务端返回 HTML 错误页（无标题）".to_string()
        } else {
            format!("服务端返回 HTML 错误页：{title}")
        };
    }
    text.chars().take(500).collect::<String>()
}

/// 通用 HTTP 请求，返回原始响应（状态码 + 响应头 + 响应体），可选是否跟随重定向。
///
/// 供需要读取响应头（如 302 的 `Location`）或自行处理非 JSON 响应的场景使用；
/// 其余场景优先用 [`http_request_with_proxy`]。失败（网络错误 / 代理配置错误）
/// 返回 `(0, HashMap::new(), 错误信息)`，由调用方根据 status 判断。
pub async fn http_request_raw(
    url: &str,
    method: &str,
    body: Option<Value>,
    headers: Option<&HashMap<String, String>>,
    proxy: Option<&str>,
    follow_redirects: bool,
) -> (u16, HashMap<String, String>, String) {
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let client = match proxy.map(str::trim).filter(|value| !value.is_empty()) {
        Some(proxy) => {
            let mut builder = http_client_builder().proxy(match reqwest::Proxy::all(proxy) {
                Ok(proxy) => proxy,
                Err(e) => return (0, HashMap::new(), format!("代理地址无效: {e}")),
            });
            if !follow_redirects {
                builder = builder.redirect(reqwest::redirect::Policy::none());
            }
            match builder.build() {
                Ok(client) => client,
                Err(e) => return (0, HashMap::new(), format!("代理客户端创建失败: {e}")),
            }
        }
        None => {
            if follow_redirects {
                http_client().clone()
            } else {
                match http_client_builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                {
                    Ok(client) => client,
                    Err(e) => return (0, HashMap::new(), format!("客户端创建失败: {e}")),
                }
            }
        }
    };
    let mut req = client.request(method, url);
    req = req.header("Content-Type", "application/json");
    if let Some(h) = headers {
        for (k, v) in h {
            req = req.header(k, v);
        }
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let mut resp_headers = HashMap::new();
            for (k, v) in resp.headers() {
                if let Ok(vs) = v.to_str() {
                    resp_headers.insert(k.as_str().to_string(), vs.to_string());
                }
            }
            let text = resp.text().await.unwrap_or_default();
            (status, resp_headers, text)
        }
        Err(e) => (0, HashMap::new(), e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归 issue #94：网关 401 返回的整页 HTML 要归一化为可读信息，
    /// 不能把 `<html>…` 原样塞进通知与界面卡片。
    #[test]
    fn normalize_error_body_extracts_html_title() {
        let html = "<html>\n<head><title>401 Authorization Required</title></head>\n\
                    <body>\n<center><h1>401 Authorization Required</h1></center>\n\
                    <hr><center>openresty</center>\n</body>\n</html>\n";
        assert_eq!(
            normalize_error_body(html),
            "服务端返回 HTML 错误页：401 Authorization Required"
        );

        assert_eq!(
            normalize_error_body("<!DOCTYPE html><html><body>boom</body></html>"),
            "服务端返回 HTML 错误页（无标题）"
        );

        // 非 HTML 错误体保持原有截断行为。
        let plain = "plain gateway error";
        assert_eq!(normalize_error_body(plain), plain);
        let long = "x".repeat(600);
        assert_eq!(normalize_error_body(&long).chars().count(), 500);
    }

    #[test]
    fn default_http_user_agent_matches_official_chrome_desktop() {
        assert_eq!(
            DEFAULT_HTTP_USER_AGENT,
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
        );
        let _ = http_client_builder();
    }
}
