//! Trae 会话记录导出（移植自 trae-session-export/trae_web.py）。
//!
//! 输入是解密库（`trae_decrypt` 产出的明文 SQLite），输出对话 Markdown 与批量 zip。
//! 覆盖：会话列表、会话信息、对话解析（user / assistant 交替）、单会话导出、批量打包。

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Serialize;
use serde_json::{json, Value};

use crate::modules::config::store_dir;
use crate::modules::trae_discover::get_client;

/// 解密库路径：`<工具目录>/trae/decrypted/<clientKey>.db`。
pub fn decrypted_db_path(client_key: &str) -> PathBuf {
    store_dir().join("trae").join("decrypted").join(format!("{client_key}.db"))
}

/// 导出目录：`<工具目录>/trae/export/`。
pub fn export_dir() -> PathBuf {
    store_dir().join("trae").join("export")
}

/// 整库备份目录（删除会话前）。
pub fn backup_dir() -> PathBuf {
    store_dir().join("trae").join("backup")
}

/// 会话回收站目录（删除会话后文件移入，可恢复）。
pub fn deleted_sessions_dir() -> PathBuf {
    store_dir().join("trae").join("deleted_sessions")
}

/// 会话 ID 合法性：20~24 位十六进制（不含 `sess_` 前缀）。
pub fn is_session_id(s: &str) -> bool {
    let t = s.trim().to_lowercase();
    (20..=24).contains(&t.len()) && t.chars().all(|c| c.is_ascii_hexdigit())
}

fn prefix_of(client_key: &str) -> &'static str {
    match client_key {
        "trae-cn" => "traecn_session",
        _ => "trae_session",
    }
}

pub fn label_of(client_key: &str) -> String {
    get_client(client_key).map(|c| c.label).unwrap_or(client_key).to_string()
}

fn format_ts(ts: &rusqlite::types::Value) -> String {
    match ts {
        rusqlite::types::Value::Integer(i) => {
            let secs = if *i > 1_000_000_000_000 { *i / 1000 } else { *i };
            chrono::DateTime::from_timestamp(secs, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| i.to_string())
        }
        rusqlite::types::Value::Text(s) => s.clone(),
        _ => String::new(),
    }
}

/// 文件名安全化（非法字符 → `_`）。
pub fn safe_filename(name: &str) -> String {
    let t: String = name
        .chars()
        .map(|c| if "\\/:*?\"<>|\r\n\t".contains(c) { '_' } else { c })
        .collect();
    let t = t.trim().to_string();
    if t.is_empty() {
        "session".into()
    } else {
        t
    }
}

/// 按字节上限安全截断：不切断多字节 UTF-8 字符，避免 `&s[..n]` 的 char 边界 panic。
pub fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// 打开解密库（明文 SQLite）。不存在返回错误。
pub(crate) fn open_decrypted(client_key: &str) -> Result<Connection, String> {
    let path = decrypted_db_path(client_key);
    if !path.exists() {
        return Err(format!(
            "未找到解密数据库：{}\n请先在「Trae 记录」页运行「扫描密钥并解密」。",
            path.display()
        ));
    }
    Connection::open(&path).map_err(|e| format!("打开解密库失败: {e}"))
}

// ---------------------------------------------------------------------------
// 会话列表
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub title: String,
    pub created: String,
    pub updated: String,
    pub turns: i64,
    /// 归属账号 uid（project.user_id；无归属为空串）。
    pub owner_uid: String,
    /// 归属账号显示名（昵称或 uid 尾号；无归属为「（无归属）」）。
    pub owner_label: String,
}

/// 列出全部会话（按最后活动时间倒序），带归属账号信息。
pub fn list_sessions(client_key: &str) -> Result<Vec<SessionInfo>, String> {
    let conn = open_decrypted(client_key)?;
    let mut stmt = conn
        .prepare(
            "SELECT s.session_id, s.session_title, s.created_at, s.updated_at, \
                    COALESCE(p.user_id, '') AS owner_uid \
             FROM chat_session s \
             LEFT JOIN project p ON s.project_id = p.project_id \
             ORDER BY ifnull(s.updated_at, s.created_at) DESC",
        )
        .map_err(|e| format!("会话列表查询失败: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, rusqlite::types::Value>(2)?,
                row.get::<_, rusqlite::types::Value>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| format!("会话列表查询失败: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("会话列表读取失败: {e}"))?;

    let turns_map: HashMap<String, i64> = conn
        .prepare(
            "SELECT session_id, count(*) FROM chat_message \
             WHERE message_role='user' AND ifnull(deleted_at,0)=0 GROUP BY session_id",
        )
        .map_err(|e| format!("轮数统计失败: {e}"))?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
        .map_err(|e| format!("轮数统计失败: {e}"))?
        .collect::<Result<HashMap<_, _>, _>>()
        .map_err(|e| format!("轮数统计失败: {e}"))?;

    Ok(rows
        .into_iter()
        .map(|(id, title, created, updated, owner_uid)| {
            let owner_label = if owner_uid.is_empty() {
                "（无归属）".into()
            } else {
                crate::modules::trae_vault::account_label(client_key, &owner_uid)
            };
            SessionInfo {
                id: id.clone(),
                title: title.trim().to_string(),
                created: format_ts(&created),
                updated: format_ts(&updated),
                turns: turns_map.get(&id).copied().unwrap_or(0),
                owner_uid,
                owner_label,
            }
        })
        .collect())
}

// ---------------------------------------------------------------------------
// 对话解析（字段语义与 trae_web.py 一致）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Turn {
    pub role: String,
    pub text: String,
    /// 该轮出现过的工具名（去重，供记忆交接统计）。
    pub tools: Vec<String>,
}

/// `chat_message_general.content` → 用户输入文本（干净原文）。
fn general_text(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(arr)) => {
            let mut parts = Vec::new();
            for p in arr {
                if let Value::Object(m) = p {
                    let t = m
                        .get("text_content")
                        .and_then(|v| v.as_str())
                        .or_else(|| m.get("text").and_then(|v| v.as_str()));
                    if let Some(t) = t {
                        let t = t.trim();
                        if !t.is_empty() {
                            parts.push(t.to_string());
                        }
                    }
                }
            }
            parts.join("\n").trim().to_string()
        }
        _ => raw.trim().to_string(),
    }
}

/// `history_v2.messages` → assistant 过程文本（多段 text 按顺序拼接）。
fn assistant_text(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let Ok(data) = serde_json::from_str::<Value>(raw) else {
        return String::new();
    };
    let Some(raw_msgs) = data.get("raw_messages").and_then(|v| v.as_array()) else {
        return String::new();
    };
    let mut parts = Vec::new();
    for m in raw_msgs {
        if m.get("role").and_then(|v| v.as_str()) != Some("assistant") {
            continue;
        }
        match m.get("content") {
            Some(Value::Array(arr)) => {
                for p in arr {
                    if p.get("type").and_then(|v| v.as_str()) == Some("text") {
                        if let Some(t) = p.get("text").and_then(|v| v.as_str()) {
                            let t = t.trim();
                            if !t.is_empty() {
                                parts.push(t.to_string());
                            }
                        }
                    }
                }
            }
            Some(Value::String(s)) => {
                let s = s.trim();
                if !s.is_empty() {
                    parts.push(s.to_string());
                }
            }
            _ => {}
        }
    }
    parts.join("\n\n").trim().to_string()
}

/// `chat_message_task.content` → plan_item.tool_call_info.params.summary（该轮最终完整回答）。
fn task_summary(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let Ok(data) = serde_json::from_str::<Value>(raw) else {
        return String::new();
    };
    let Some(msgs) = data.get("messages").and_then(|v| v.as_array()) else {
        return String::new();
    };
    let mut parts = Vec::new();
    for m in msgs {
        let s = m
            .get("plan_item")
            .and_then(|p| p.get("tool_call_info"))
            .and_then(|t| t.get("params"))
            .and_then(|p| p.get("summary"))
            .and_then(|v| v.as_str());
        if let Some(s) = s {
            let s = s.trim();
            if !s.is_empty() {
                parts.push(s.to_string());
            }
        }
    }
    parts.join("\n\n").trim().to_string()
}

/// 一次工具调用 → markdown 渲染块（input 全保，防超大）。
fn render_trae_tool(name: &str, params: &Value) -> String {
    let params = if params.is_null() { &json!({}) } else { params };

    let code_block = |s: &str, lang: &str| format!("```{lang}\n{s}\n```");

    let mut lines: Vec<String> = vec![format!("🔧 **[{name}]**")];
    let mut body: Vec<String> = Vec::new();
    let get = |k: &str| params.get(k).and_then(|v| v.as_str()).unwrap_or("");
    match name {
        "Write" => {
            body.push(format!("创建文件：`{}`", get("file_path")));
            body.push(code_block(get("content"), ""));
        }
        "Edit" => {
            body.push(format!("编辑文件：`{}`", get("file_path")));
            let old = get("old_string");
            let new = get("new_string");
            let content = get("content");
            if !old.is_empty() {
                body.push(format!("旧内容：\n{}", code_block(old, "")));
            }
            if !new.is_empty() {
                body.push(format!("新内容：\n{}", code_block(new, "")));
            }
            if !content.is_empty() {
                body.push(code_block(content, ""));
            }
        }
        "RunCommand" | "CheckCommandStatus" | "StopCommand" => {
            let cmd = get("command");
            if !cmd.is_empty() {
                body.push(code_block(cmd, "bash"));
            }
        }
        "Read" => body.push(format!("读取文件：`{}`", get("file_path"))),
        "Grep" => body.push(format!(
            "搜索 `{}`：{}",
            get("path"),
            get("pattern")
        )),
        "LS" => body.push(format!("列目录：`{}`", get("path"))),
        "Glob" => body.push(format!("匹配 `{}`：{}", get("path"), get("pattern"))),
        "DeleteFile" => body.push(format!("删除文件：{}", get("file_paths"))),
        "TodoWrite" => {
            if let Some(todos) = params.get("todos").and_then(|v| v.as_array()) {
                for t in todos {
                    if let Value::Object(m) = t {
                        body.push(format!(
                            "- [{}] {}",
                            m.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                            m.get("content").and_then(|v| v.as_str()).unwrap_or("")
                        ));
                    } else {
                        body.push(format!("- {t}"));
                    }
                }
            }
        }
        "WebSearch" => body.push(format!("搜索：{}", get("query"))),
        "AskUserQuestion" => {
            if let Some(qs) = params.get("questions").and_then(|v| v.as_array()) {
                for q in qs {
                    if let Value::Object(m) = q {
                        body.push(format!(
                            "提问：{}",
                            m.get("question").and_then(|v| v.as_str()).unwrap_or("")
                        ));
                    } else {
                        body.push(format!("提问：{q}"));
                    }
                }
            }
        }
        "finish" | "CompactFake" => return String::new(),
        _ => {
            let s = serde_json::to_string(params).unwrap_or_else(|_| format!("{params}"));
            let s = if s.len() > 1500 {
                format!("{} ...(截断)", truncate_utf8(&s, 1500))
            } else {
                s
            };
            body.push(code_block(&s, "json"));
        }
    }
    lines.extend(body);
    lines.join("\n").trim().to_string()
}

/// `chat_message_task.content` → (渲染块列表, 工具名列表)。
fn task_tool_blocks(raw: &str) -> (Vec<String>, Vec<String>) {
    let mut blocks = Vec::new();
    let mut names = Vec::new();
    let Ok(data) = serde_json::from_str::<Value>(raw) else {
        return (blocks, names);
    };
    let Some(msgs) = data.get("messages").and_then(|v| v.as_array()) else {
        return (blocks, names);
    };
    for m in msgs {
        let Some(pi) = m.get("plan_item") else {
            continue;
        };
        let Some(ti) = pi.get("tool_call_info") else {
            continue;
        };
        let Some(name) = ti.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if name == "finish" || name == "CompactFake" {
            continue;
        }
        let params = ti.get("params").cloned().unwrap_or_else(|| json!({}));
        if name == "Edit"
            && params.get("old_string").and_then(|v| v.as_str()).unwrap_or("").is_empty()
            && params.get("new_string").and_then(|v| v.as_str()).unwrap_or("").is_empty()
            && params.get("content").and_then(|v| v.as_str()).unwrap_or("").is_empty()
        {
            continue;
        }
        let block = render_trae_tool(name, &params);
        if !block.is_empty() {
            blocks.push(block);
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
        }
    }
    (blocks, names)
}

/// `server_history_info.messages` 增量流重组：以 user 为界分组 assistant 文本。
/// 返回 (分组文本, 每组工具名) 或 None。
fn server_stream_groups(conn: &Connection, sid: &str) -> Option<(Vec<Vec<String>>, Vec<Vec<String>>)> {
    let mut groups: Vec<Vec<String>> = Vec::new();
    let mut names: Vec<Vec<String>> = Vec::new();
    let mut stmt = conn
        .prepare(
            "SELECT messages FROM server_history_info WHERE conversation_id=? \
             ORDER BY created_at, rowid",
        )
        .ok()?;
    let rows: Vec<String> = stmt
        .query_map([sid], |row| row.get::<_, String>(0))
        .ok()?
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if rows.is_empty() {
        return None;
    }
    for raw in rows {
        let Ok(data) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(raw_msgs) = data.get("raw_messages").and_then(|v| v.as_array()) else {
            continue;
        };
        for m in raw_msgs {
            let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role == "user" {
                groups.push(Vec::new());
                names.push(Vec::new());
                continue;
            }
            if role != "assistant" {
                continue;
            }
            if groups.is_empty() {
                groups.push(Vec::new());
                names.push(Vec::new());
            }
            let mut texts: Vec<String> = Vec::new();
            match m.get("content") {
                Some(Value::Array(arr)) => {
                    for p in arr {
                        if p.get("type").and_then(|v| v.as_str()) == Some("text") {
                            if let Some(t) = p.get("text").and_then(|v| v.as_str()) {
                                let t = t.trim();
                                if !t.is_empty() {
                                    texts.push(t.to_string());
                                }
                            }
                        }
                    }
                }
                Some(Value::String(s)) => {
                    let s = s.trim();
                    if !s.is_empty() {
                        texts.push(s.to_string());
                    }
                }
                _ => {}
            }
            if let Some(tcs) = m.get("tool_calls").and_then(|v| v.as_array()) {
                for tc in tcs {
                    let fc = tc.get("function_call").cloned().unwrap_or(Value::Null);
                    let name = fc.get("name").and_then(|v| v.as_str()).unwrap_or("?").to_string();
                    let args = fc.get("arguments").and_then(|v| v.as_str()).unwrap_or("{}");
                    let params: Value = serde_json::from_str(args)
                        .unwrap_or_else(|_| json!({ "raw": args.chars().take(500).collect::<String>() }));
                    let block = render_trae_tool(&name, &params);
                    if !block.is_empty() {
                        texts.push(block);
                        let g = names.last_mut().unwrap();
                        if !g.iter().any(|n| n == &name) {
                            g.push(name);
                        }
                    }
                }
            }
            let g = groups.last_mut().unwrap();
            for t in texts {
                if g.is_empty() || g.last().unwrap() != &t {
                    g.push(t);
                }
            }
        }
    }
    if groups.is_empty() {
        None
    } else {
        Some((groups, names))
    }
}

/// 取一个会话的完整对话（user / assistant 交替，含每轮工具名）。
pub fn fetch_conversation(conn: &Connection, sid: &str) -> Result<Vec<Turn>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT message_id, message_role FROM chat_message \
             WHERE session_id=? AND ifnull(deleted_at,0)=0 ORDER BY message_index",
        )
        .map_err(|e| format!("会话消息查询失败: {e}"))?;
    let rows: Vec<(String, String)> = stmt
        .query_map([sid], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|e| format!("会话消息查询失败: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("会话消息读取失败: {e}"))?;

    let asst_mids: Vec<String> = rows
        .iter()
        .filter(|(_, role)| role == "assistant")
        .map(|(mid, _)| mid.clone())
        .collect();

    let mut summaries: Vec<String> = Vec::with_capacity(asst_mids.len());
    let mut blocks_list: Vec<Vec<String>> = Vec::with_capacity(asst_mids.len());
    let mut task_names: Vec<Vec<String>> = Vec::with_capacity(asst_mids.len());
    for mid in &asst_mids {
        let raw = conn
            .query_row(
                "SELECT content FROM chat_message_task WHERE message_id=?",
                [mid],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_default();
        summaries.push(task_summary(&raw));
        let (blocks, names) = task_tool_blocks(&raw);
        blocks_list.push(blocks);
        task_names.push(names);
    }

    let groups = server_stream_groups(conn, sid);
    let asst_texts: Option<Vec<String>> = if let Some((g, _)) = &groups {
        if g.len() == asst_mids.len() {
            Some(g.iter().map(|x| x.join("\n\n")).collect())
        } else {
            None
        }
    } else {
        None
    };
    let group_names: Option<Vec<Vec<String>>> = groups.map(|(_, n)| n);

    let mut turns: Vec<Turn> = Vec::with_capacity(rows.len());
    let mut asst_i = 0usize;
    for (mid, role) in rows {
        if role == "user" {
            let raw = conn
                .query_row(
                    "SELECT content FROM chat_message_general WHERE message_id=?",
                    [&mid],
                    |row| row.get::<_, String>(0),
                )
                .unwrap_or_default();
            turns.push(Turn { role, text: general_text(&raw), tools: Vec::new() });
        } else {
            let i = asst_i;
            asst_i += 1;
            let text: String;
            let mut tools: Vec<String> = group_names
                .as_ref()
                .and_then(|n| n.get(i))
                .cloned()
                .unwrap_or_default();
            if let Some(texts) = &asst_texts {
                let mut pieces: Vec<String> = vec![texts[i].clone()];
                pieces.extend(blocks_list[i].iter().cloned().filter(|x| !x.is_empty()));
                let s = &summaries[i];
                if !s.is_empty() && !texts[i].contains(s.as_str()) {
                    pieces.push(s.clone());
                }
                text = pieces.join("\n\n");
            } else {
                let h_rows: Vec<String> = conn
                    .prepare(
                        "SELECT messages FROM history_v2 \
                         WHERE message_id=? AND ifnull(deleted_at,0)=0 ORDER BY id",
                    )
                    .map_err(|e| format!("history_v2 查询失败: {e}"))?
                    .query_map([&mid], |row| row.get::<_, String>(0))
                    .map_err(|e| format!("history_v2 查询失败: {e}"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("history_v2 读取失败: {e}"))?;
                let joined: Vec<String> = h_rows
                    .iter()
                    .map(|r| assistant_text(r))
                    .filter(|x| !x.is_empty())
                    .collect();
                let mut pieces: Vec<String> = vec![joined.join("\n\n")];
                pieces.extend(blocks_list[i].iter().cloned().filter(|x| !x.is_empty()));
                let s = &summaries[i];
                if !s.is_empty() && !pieces.iter().any(|p| p == s) {
                    pieces.push(s.clone());
                }
                text = pieces.join("\n\n");
            }
            for n in &task_names[i] {
                if !tools.iter().any(|t| t == n) {
                    tools.push(n.clone());
                }
            }
            turns.push(Turn {
                role,
                text: text.trim().to_string(),
                tools,
            });
        }
    }
    Ok(turns)
}

// ---------------------------------------------------------------------------
// MD 生成与导出
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ExportMeta {
    pub title: String,
    pub turns: usize,
    pub messages: usize,
    pub empty_user: usize,
    pub empty_assistant: usize,
    pub chars: usize,
}

/// 生成对话记录 MD，返回 (md 文本, 统计)。
pub fn build_chat_md(client_key: &str, session_id: &str) -> Result<(String, ExportMeta), String> {
    if !is_session_id(session_id) {
        return Err("会话 ID 格式不正确，应为 20~24 位十六进制".into());
    }
    let conn = open_decrypted(client_key)?;
    let row = conn
        .query_row(
            "SELECT session_title, created_at, updated_at FROM chat_session WHERE session_id=?",
            [session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, rusqlite::types::Value>(1)?,
                    row.get::<_, rusqlite::types::Value>(2)?,
                ))
            },
        )
        .map_err(|_| format!("会话 {session_id} 不在当前数据源中"))?;
    let (title, created, updated) = row;
    let turns = fetch_conversation(&conn, session_id)?;

    let label = label_of(client_key);
    let display = if title.trim().is_empty() {
        session_id.to_string()
    } else {
        title.trim().to_string()
    };
    let user_turns = turns.iter().filter(|t| t.role == "user").count();

    let mut l: Vec<String> = Vec::new();
    l.push(format!("# {display}"));
    l.push(String::new());
    l.push(format!("> 来源: {label}  |  Session: `{session_id}`"));
    l.push(format!(
        "> 创建: {}  |  更新: {}  |  轮数: {user_turns}",
        format_ts(&created),
        format_ts(&updated)
    ));
    l.push(String::new());
    l.push("---".into());
    l.push(String::new());

    let mut empty_user = 0usize;
    let mut empty_asst = 0usize;
    for t in &turns {
        let role_name = if t.role == "user" { "user" } else { "assistant" };
        if t.role == "user" && t.text.is_empty() {
            empty_user += 1;
        }
        if t.role == "assistant" && t.text.is_empty() {
            empty_asst += 1;
        }
        l.push(format!("## {role_name}"));
        l.push(String::new());
        l.push(if t.text.is_empty() { "（无记录）".into() } else { t.text.clone() });
        l.push(String::new());
        l.push("---".into());
        l.push(String::new());
    }

    let meta = ExportMeta {
        title: display,
        turns: user_turns,
        messages: turns.len(),
        empty_user,
        empty_assistant: empty_asst,
        chars: turns.iter().map(|t| t.text.len()).sum(),
    };
    Ok((l.join("\n"), meta))
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportedFile {
    pub session_id: String,
    pub filename: String,
    pub path: String,
    pub size_kb: f64,
    pub stats: ExportMeta,
}

/// 导出单个会话为 MD 文件（导出目录内自动去重命名）。
pub fn export_session(client_key: &str, session_id: &str) -> Result<ExportedFile, String> {
    let (md, meta) = build_chat_md(client_key, session_id)?;
    let dir = export_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建导出目录失败: {e}"))?;
    let base = format!(
        "{}_{}_{}.md",
        prefix_of(client_key),
        safe_filename(&meta.title),
        &session_id[..session_id.len().min(8)]
    );
    let mut path = dir.join(&base);
    let mut n = 1usize;
    while path.exists() {
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        path = dir.join(format!("{stem}_{n}.md"));
        n += 1;
    }
    std::fs::write(&path, md).map_err(|e| format!("写导出文件失败: {e}"))?;
    let size_kb = std::fs::metadata(&path)
        .map(|m| m.len() as f64 / 1024.0)
        .unwrap_or(0.0);
    Ok(ExportedFile {
        session_id: session_id.to_string(),
        filename: path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
        path: path.to_string_lossy().into_owned(),
        size_kb: (size_kb * 10.0).round() / 10.0,
        stats: meta,
    })
}

/// 会话信息（查询会话信息用）。
pub fn session_detail(client_key: &str, session_id: &str) -> Result<Value, String> {
    if !is_session_id(session_id) {
        return Err("会话 ID 格式不正确，应为 20~24 位十六进制".into());
    }
    let conn = open_decrypted(client_key)?;
    let row = conn
        .query_row(
            "SELECT session_title, created_at, updated_at FROM chat_session WHERE session_id=?",
            [session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, rusqlite::types::Value>(1)?,
                    row.get::<_, rusqlite::types::Value>(2)?,
                ))
            },
        )
        .map_err(|_| format!("会话 {session_id} 不在当前数据源中"))?;
    let (title, created, updated) = row;
    let turns = fetch_conversation(&conn, session_id)?;
    let title = if title.trim().is_empty() {
        session_id.to_string()
    } else {
        title.trim().to_string()
    };
    Ok(json!({
        "session_id": session_id,
        "title": title,
        "source": label_of(client_key),
        "turns": turns.iter().filter(|t| t.role == "user").count(),
        "messages": turns.len(),
        "created": format_ts(&created),
        "updated": format_ts(&updated),
    }))
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportAllReport {
    pub path: String,
    pub filename: String,
    pub ok: usize,
    pub failed: Vec<String>,
    pub total: usize,
}

/// 一键导出全部会话为 zip（可跨数据源）。
pub fn export_all(sources: &[String]) -> Result<ExportAllReport, String> {
    if sources.is_empty() {
        return Err("未指定数据源".into());
    }
    let dir = export_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建导出目录失败: {e}"))?;
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let tag = sources
        .iter()
        .map(|s| if s == "trae-cn" { "traecn" } else { "solo" })
        .collect::<Vec<_>>()
        .join("_");
    let fname = format!("trae_chats_{tag}_{stamp}.zip");
    let path = dir.join(&fname);

    let file = std::fs::File::create(&path).map_err(|e| format!("创建 zip 失败: {e}"))?;
    let mut zw = zip::ZipWriter::new(file);
    let opts = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut ok = 0usize;
    let mut total = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut any_found = false;

    for src in sources {
        let sessions = list_sessions(src);
        match sessions {
            Err(e) => failed.push(format!("{}: {e}", label_of(src))),
            Ok(list) => {
                if !list.is_empty() {
                    any_found = true;
                }
                total += list.len();
                for s in &list {
                    match build_chat_md(src, &s.id) {
                        Ok((md, meta)) => {
                            let name = format!(
                                "{}_{}_{}.md",
                                prefix_of(src),
                                safe_filename(&meta.title),
                                &s.id[..s.id.len().min(8)]
                            );
                            let _ = zw.start_file(name, opts);
                            let _ = zw.write_all(md.as_bytes());
                            ok += 1;
                        }
                        Err(e) => failed.push(format!("{}: {e}", s.id)),
                    }
                }
            }
        }
    }

    if !any_found {
        let _ = zw.finish();
        let _ = std::fs::remove_file(&path);
        let msg = if failed.is_empty() {
            "未找到任何会话".to_string()
        } else {
            format!("未找到任何会话；{}", failed.join("；"))
        };
        return Err(msg);
    }

    if !failed.is_empty() {
        let note = format!(
            "以下会话导出失败（数据异常，不影响其余文件）：\n\n{}",
            failed.join("\n")
        );
        let _ = zw.start_file("_导出失败清单.txt", opts);
        let _ = zw.write_all(note.as_bytes());
    }

    zw.finish().map_err(|e| format!("完成 zip 失败: {e}"))?;
    Ok(ExportAllReport {
        path: path.to_string_lossy().into_owned(),
        filename: fname,
        ok,
        failed,
        total,
    })
}

/// 便捷：删除文件（供前端清理过期 zip 等）。
pub fn remove_file_quiet(path: &Path) {
    let _ = std::fs::remove_file(path);
}
