//! Trae 跨账号「交接记忆」——把源账号在解密库里的会话进度，整理成**目标账号的 AI 能接着干**的形式。
//!
//! 数据来源（用户确认）：**解密库自动生成**（`trae_decrypt` 产出的明文 SQLite，`trae_export` 负责解析）。
//! 每个会话压成一条交接条目：意图 = 第一条 user 消息；结果 = 最后一条 assistant 文本；
//! 做了什么 = 该会话出现过的工具名统计。
//!
//! 落点（写入只新增、不覆盖）：
//!   · 项目工作目录 `<项目>/TRAE_交接记忆.md`      磁盘路径，天然跨账号
//!   · 项目规则     `<项目>/.trae/rules/trae-switch-handoff.md`  客户端每次对话注入 prompt
//!   · Trae 记忆库  `<记忆项目目录>/<今天>/topics.md` 追加（只追加，不覆盖）
//!   · 工具目录     `<工具目录>/trae/handoff/<clientKey>/<时间>_<项目>/`  完整归档，保证不丢
//!
//! 绝不改动客户端自己写的 `session_memory_*.jsonl`。

use chrono::Local;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::modules::config::store_dir;
use crate::modules::trae_discover::{get_client, user_data_dir};
use crate::modules::trae_export::{self, SessionInfo};

/// 工作目录里的交接文件名（用户在文件树里一眼能看到）。
pub const HANDOFF_FILE_PREFIX: &str = "TRAE_交接记忆";

/// 项目规则文件名（客户端把 `<项目>/.trae/rules/**.md` 一律当项目规则注入 prompt）。
pub const RULE_FILE_NAME: &str = "trae-switch-handoff.md";

/// 交接文档默认保留的条目数（按时间取最近的）。
const MAX_ITEMS: usize = 20;

/// 单条交接条目（会话级）。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HandoffItem {
    pub session_id: String,
    pub title: String,
    /// `YYYY-MM-DD HH:mm:ss`（空表示无时间）。
    pub time: String,
    pub intent: String,
    pub actions: Vec<String>,
    pub outcome: String,
    pub learned: Vec<String>,
}

/// 交接包：markdown 正文 + 原生记忆片段 + 元数据（纯组装，不碰文件系统）。
#[derive(Debug, Clone)]
pub struct HandoffPackage {
    pub client_key: String,
    pub project_path: String,
    pub project_name: String,
    pub account_id: Option<String>,
    pub items: Vec<HandoffItem>,
    /// 因超过 [`MAX_ITEMS`] 被省略的条数。
    pub dropped: usize,
    pub next_steps: Vec<String>,
    pub key_files: Vec<String>,
    pub note: Option<String>,
    pub markdown: String,
    pub rule_markdown: String,
    pub topics_lines: Vec<String>,
    pub session_memory: Vec<Value>,
    pub generated_at: String,
}

// ---------------------------------------------------------------------------
// 纯工具
// ---------------------------------------------------------------------------

/// 单行化：交接摘要里换行、连续空白都会破坏可读性与单行格式。
fn one_line(s: &str, cap: usize) -> String {
    let t: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = t.trim();
    if t.is_empty() {
        return String::new();
    }
    if cap == 0 || t.chars().count() <= cap {
        return t.to_string();
    }
    let mut out: String = t.chars().take(cap).collect();
    out.push('…');
    out
}

/// 路径归一化：反斜杠转正斜杠、折叠重复斜杠、去尾斜杠、小写。
fn norm_path(s: &str) -> String {
    let mut t = s.replace('\\', "/");
    while t.contains("//") {
        t = t.replace("//", "/");
    }
    while t.ends_with('/') {
        t.pop();
    }
    t.to_lowercase()
}

/// Trae 的「数据根」：放 `work/`、`memory/` 的那一层。
/// 国内版两套客户端（Trae CN / TRAE SOLO CN）共用 `~/.trae-cn`；国际版按 `.trae` 推导。
pub fn trae_home(client_key: &str) -> PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    let is_intl = client_key.ends_with("-intl");
    let names: [&str; 2] = if is_intl { [".trae", ".trae-cn"] } else { [".trae-cn", ".trae"] };
    for n in names {
        let p = home.join(n);
        if p.is_dir() {
            return p;
        }
    }
    home.join(names[0])
}

/// 统计工具名（按次数降序，最多 12 种）。
fn summarize_tools(tools: &[String]) -> Vec<String> {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for t in tools {
        *counts.entry(t.as_str()).or_insert(0) += 1;
    }
    let mut entries: Vec<(String, usize)> = counts
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    entries.truncate(12);
    entries.iter().map(|(name, count)| format!("{name}×{count}")).collect()
}

// ---------------------------------------------------------------------------
// 数据采集（解密库自动生成）
// ---------------------------------------------------------------------------

/// 采集源账号（某数据源）的会话进度，压成交接条目。
///
/// `session_ids` 给定时只处理这些会话；否则取解密库里最近 [`MAX_ITEMS`] 条会话。
/// 无 user 消息、无 assistant 文本、也无工具的会话跳过。
pub fn gather_items(
    client_key: &str,
    session_ids: Option<&[String]>,
) -> Result<Vec<HandoffItem>, String> {
    let conn = trae_export::open_decrypted(client_key)?;

    let sessions: Vec<SessionInfo> = match session_ids {
        Some(ids) if !ids.is_empty() => {
            let all = trae_export::list_sessions(client_key)?;
            let mut picked = Vec::new();
            for id in ids {
                let id = id.trim().to_lowercase();
                if !trae_export::is_session_id(&id) {
                    return Err(format!("会话 ID 格式不正确：{id}"));
                }
                match all.iter().find(|s| s.id == id) {
                    Some(s) => picked.push(s.clone()),
                    None => return Err(format!("会话 {id} 不在当前数据源中")),
                }
            }
            picked
        }
        _ => trae_export::list_sessions(client_key)?,
    };

    let mut items: Vec<HandoffItem> = Vec::new();
    for s in sessions {
        let turns = match trae_export::fetch_conversation(&conn, &s.id) {
            Ok(t) => t,
            Err(e) => return Err(format!("会话 {} 解析失败：{e}", s.id)),
        };
        let mut intent = String::new();
        let mut outcome = String::new();
        let mut tools: Vec<String> = Vec::new();
        for t in &turns {
            for n in &t.tools {
                if !tools.iter().any(|x| x == n) {
                    tools.push(n.clone());
                }
            }
            if t.role == "user" {
                if intent.is_empty() && !t.text.trim().is_empty() {
                    intent = one_line(&t.text, 400);
                }
            } else if !t.text.trim().is_empty() {
                // 结果只保留最后一条 assistant 文本
                outcome = one_line(&t.text, 1200);
            }
        }
        if intent.is_empty() && outcome.is_empty() && tools.is_empty() {
            continue;
        }
        items.push(HandoffItem {
            session_id: s.id.clone(),
            title: one_line(&s.title, 80),
            time: s.updated.clone(),
            intent,
            actions: summarize_tools(&tools),
            outcome,
            learned: Vec::new(),
        });
    }

    items.sort_by(|a, b| b.time.cmp(&a.time));
    if items.is_empty() {
        return Err("解密库里没有可提取的会话记录".to_string());
    }
    Ok(items)
}

// ---------------------------------------------------------------------------
// 组装
// ---------------------------------------------------------------------------

/// 生成交接包（纯函数，不碰文件系统）。
#[allow(clippy::too_many_arguments)]
pub fn build_handoff(
    client_key: &str,
    items: Vec<HandoffItem>,
    project_path: String,
    project_name: Option<&str>,
    account_id: Option<&str>,
    next_steps: Vec<String>,
    key_files: Vec<String>,
    note: Option<&str>,
) -> HandoffPackage {
    let generated_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let project_name = project_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            Path::new(&project_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "未指定项目".to_string())
        });
    let (kept, dropped) = if items.len() > MAX_ITEMS {
        (items[..MAX_ITEMS].to_vec(), items.len() - MAX_ITEMS)
    } else {
        (items.clone(), 0)
    };
    let next_steps: Vec<String> = next_steps
        .iter()
        .map(|s| one_line(s, 0))
        .filter(|s| !s.is_empty())
        .collect();
    let key_files: Vec<String> = key_files
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let note = note.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let account_id = account_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let markdown = build_markdown(
        &project_name,
        &project_path,
        client_key,
        account_id.as_deref(),
        &kept,
        dropped,
        &next_steps,
        &key_files,
        note.as_deref(),
        &generated_at,
    );
    let rule_markdown = build_rule_markdown(
        &project_name,
        &kept,
        &next_steps,
        &key_files,
        &generated_at,
    );

    // 原生记忆片段：topics.md 一行一条；sessionMemory 为 JSONL 每行的内容
    let topics_lines: Vec<String> = kept
        .iter()
        .map(|it| {
            format!(
                "[session_id: {} | topic_summary_time: {}]{}",
                it.session_id,
                if it.time.is_empty() { &generated_at } else { &it.time },
                one_line(if it.outcome.is_empty() { &it.intent } else { &it.outcome }, 600)
            )
        })
        .collect();
    let session_memory: Vec<Value> = kept
        .iter()
        .map(|it| {
            json!({
                "intent": it.intent,
                "actions": it.actions,
                "outcome": it.outcome,
                "learned": it.learned,
                "message_summary_time": if it.time.is_empty() { &generated_at } else { &it.time },
                "message_id": it.session_id,
                "source": "trae-switch-cn-handoff",
            })
        })
        .collect();

    HandoffPackage {
        client_key: client_key.to_string(),
        project_path,
        project_name,
        account_id,
        items: kept,
        dropped,
        next_steps,
        key_files,
        note,
        markdown,
        rule_markdown,
        topics_lines,
        session_memory,
        generated_at,
    }
}

/// 组装交接 Markdown 正文（给人、也给 AI 读）。
#[allow(clippy::too_many_arguments)]
fn build_markdown(
    project_name: &str,
    project_path: &str,
    client_key: &str,
    account_id: Option<&str>,
    items: &[HandoffItem],
    dropped: usize,
    next_steps: &[String],
    key_files: &[String],
    note: Option<&str>,
    stamp: &str,
) -> String {
    let client_label = trae_export::label_of(client_key);
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# {HANDOFF_FILE_PREFIX} · {project_name}"));
    lines.push(String::new());
    lines.push(format!(
        "> 由 **trae-switch-cn** 于 {stamp} 生成，用于**跨账号交接**。"
    ));
    let mut src = vec![client_label.to_string(), format!("工作目录 `{project_path}`")];
    if let Some(aid) = account_id {
        src.insert(1, format!("账号 `{aid}`"));
    }
    lines.push(format!("> 来源：{}", src.join(" · ")));
    lines.push(String::from(">"));
    lines.push(String::from("> **给接手的 AI：** 这是一份上一个账号留下的进度交接。请先读完本文，"));
    lines.push(String::from("> 再在**当前工作目录**里继续「下一步」。不要凭标题重做已经完成的部分。"));
    lines.push(String::new());
    lines.push(String::from("## 一、当前状态"));
    lines.push(String::new());
    lines.push(String::from("| 项 | 值 |"));
    lines.push(String::from("| --- | --- |"));
    lines.push(format!("| 项目 | {project_name} |"));
    lines.push(format!("| 工作目录 | `{project_path}` |"));
    lines.push(format!(
        "| 记录条数 | {} |",
        if dropped > 0 {
            format!("{}（共 {}，仅列最近 {} 条）", items.len(), items.len() + dropped, items.len())
        } else {
            items.len().to_string()
        }
    ));
    lines.push(format!(
        "| 最近活动 | {} |",
        items.first().map(|i| i.time.as_str()).unwrap_or("—")
    ));
    lines.push(format!("| 生成时间 | {stamp} |"));
    lines.push(String::new());
    lines.push(String::from("## 二、已完成的进展（新的在前）"));
    lines.push(String::new());
    if items.is_empty() {
        lines.push(String::from("_（没有可用的历史记录，请手动补充。）_"));
        lines.push(String::new());
    }
    for (i, it) in items.iter().enumerate() {
        lines.push(format!(
            "### {}. {} — {}",
            i + 1,
            if it.time.is_empty() { "（时间未知）" } else { it.time.as_str() },
            if it.title.is_empty() { "（未命名会话）" } else { it.title.as_str() }
        ));
        lines.push(String::new());
        lines.push(format!("- **目标**：{}", if it.intent.is_empty() { "—" } else { it.intent.as_str() }));
        if !it.actions.is_empty() {
            lines.push(format!("- **做了什么**：{}", it.actions.join("；")));
        }
        if !it.outcome.is_empty() {
            lines.push(format!("- **结果**：{}", it.outcome));
        }
        if !it.learned.is_empty() {
            lines.push(String::from("- **结论 / 约束**："));
            for l in &it.learned {
                lines.push(format!("  - {l}"));
            }
        }
        lines.push(format!("- 会话 ID：`{}`", it.session_id));
        lines.push(String::new());
    }
    if dropped > 0 {
        lines.push(format!(
            "_（更早的 {dropped} 条记录未列出；完整条目见工具目录归档的 `memory-native.json`。）_"
        ));
        lines.push(String::new());
    }

    lines.push(String::from("## 三、下一步"));
    lines.push(String::new());
    if next_steps.is_empty() {
        lines.push(String::from("- [ ] （未填写。请让用户在交接弹窗的「下一步」里补充，或由 AI 依据上文推断。）"));
    } else {
        for s in next_steps {
            lines.push(format!("- [ ] {s}"));
        }
    }
    lines.push(String::new());

    if !key_files.is_empty() {
        lines.push(String::from("## 四、关键文件"));
        lines.push(String::new());
        for f in key_files {
            lines.push(format!("- `{f}`"));
        }
        lines.push(String::new());
    }

    lines.push(String::from("## 五、环境与路径"));
    lines.push(String::new());
    lines.push(format!("- 项目目录：`{project_path}`"));
    lines.push(format!(
        "- 会话正文在解密库 `{client_key}.db`（明文 SQLite），进度信息以 Trae 的**明文记忆**为准。"
    ));
    lines.push(String::new());

    if let Some(n) = note {
        lines.push(String::from("## 六、补充说明"));
        lines.push(String::new());
        lines.push(n.to_string());
        lines.push(String::new());
    }
    lines.join("\n")
}

/// 组装项目规则文件内容（会被客户端注入**每一次**对话的 prompt，必须精简）。
fn build_rule_markdown(
    project_name: &str,
    items: &[HandoffItem],
    next_steps: &[String],
    key_files: &[String],
    stamp: &str,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# 项目交接 · {project_name}"));
    lines.push(String::new());
    lines.push(format!(
        "> 上一个账号在此项目的进度，由 **trae-switch-cn** 于 {stamp} 生成，**请勿手改**（重新生成会覆盖）。"
    ));
    lines.push(String::from("> 接手的 AI：先读完本节再动手，**不要重做已完成的部分**。"));
    lines.push(format!("> 完整记录见项目根目录 `{HANDOFF_FILE_PREFIX}.md`。"));
    lines.push(String::new());
    lines.push(String::from("## 上次做到哪"));
    if items.is_empty() {
        lines.push(String::from("- （无历史记录）"));
    } else {
        for it in items.iter().take(6) {
            let body = one_line(if it.outcome.is_empty() { &it.intent } else { &it.outcome }, 150);
            lines.push(format!(
                "- {}：{}",
                if it.time.is_empty() { "—" } else { it.time.as_str() },
                if body.is_empty() { "—" } else { body.as_str() }
            ));
        }
    }
    lines.push(String::new());
    lines.push(String::from("## 下一步"));
    if next_steps.is_empty() {
        lines.push(String::from("- [ ] （未填写，请依据上文与当前代码推断后继续）"));
    } else {
        for s in next_steps.iter().take(6) {
            lines.push(format!("- [ ] {}", one_line(s, 150)));
        }
    }
    lines.push(String::new());
    if !key_files.is_empty() {
        lines.push(String::from("## 关键文件"));
        for f in key_files.iter().take(10) {
            lines.push(format!("- `{f}`"));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// 记忆库定位（沙箱证据链，纯只读）
// ---------------------------------------------------------------------------

/// 读 `ModularData/ai-agent/sandbox/<localProjectId>.json`，还原「项目工作目录 → 会话 ID」。
struct SandboxProject {
    workspace: Option<String>,
    session_ids: Vec<String>,
}

/// 从 `dir_type=work` 的路径里取会话 ID：`…/work/<sessionId>` 的最后一段。
fn extract_work_session_id(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let idx = normalized.rfind("/work/")?;
    let rest = &normalized[idx + "/work/".len()..];
    let end = rest.find('/').unwrap_or(rest.len());
    let sid = rest[..end].trim();
    if sid.is_empty() {
        None
    } else {
        Some(sid.to_string())
    }
}

fn read_sandbox_projects(client_key: &str) -> Vec<SandboxProject> {
    let Some(client) = get_client(client_key) else {
        return Vec::new();
    };
    let dir = user_data_dir(client).join("ModularData").join("ai-agent").join("sandbox");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<SandboxProject> = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_lowercase();
        if !name.ends_with(".json") || name.ends_with("-hooks.json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        let Ok(j) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(permission) = j.get("permission").and_then(Value::as_array) else {
            continue;
        };
        let mut workspace: Option<String> = None;
        let mut session_ids: Vec<String> = Vec::new();
        for p in permission {
            let Some(v) = p.get("file_inherit_user").and_then(Value::as_str) else {
                continue;
            };
            match p.get("dir_type").and_then(Value::as_str) {
                Some("workspace") => {
                    if workspace.is_none() {
                        workspace = Some(v.to_string());
                    }
                }
                Some("work") => {
                    if let Some(sid) = extract_work_session_id(v) {
                        if !session_ids.iter().any(|s| s == &sid) {
                            session_ids.push(sid);
                        }
                    }
                }
                _ => {}
            }
        }
        out.push(SandboxProject { workspace, session_ids });
    }
    out
}

/// 找到「该项目工作目录」对应的记忆库项目目录（找不到返回 None，绝不新建）。
pub fn find_memory_project_dir(client_key: &str, project_path: &str) -> Option<PathBuf> {
    if project_path.trim().is_empty() {
        return None;
    }
    let want = norm_path(project_path);
    let mut matched_sids: Vec<String> = Vec::new();
    for p in read_sandbox_projects(client_key) {
        if let Some(w) = &p.workspace {
            if norm_path(w) == want {
                for sid in &p.session_ids {
                    if !matched_sids.iter().any(|s| s == sid) {
                        matched_sids.push(sid.clone());
                    }
                }
            }
        }
    }
    if matched_sids.is_empty() {
        return None;
    }

    let proj_root = trae_home(client_key).join("memory").join("projects");
    let Ok(entries) = std::fs::read_dir(&proj_root) else {
        return None;
    };
    for e in entries.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        if let Some(dir) = scan_project_dirs_for_sids(&e.path(), &matched_sids) {
            return Some(dir);
        }
    }
    None
}

/// 项目记忆目录下是否出现过任一目标会话 ID（`*/session_memory_<sid>.jsonl`）。
fn scan_project_dirs_for_sids(project_dir: &Path, sids: &[String]) -> Option<PathBuf> {
    let Ok(subdirs) = std::fs::read_dir(project_dir) else {
        return None;
    };
    for sub in subdirs.flatten() {
        let sub = sub.path();
        if !sub.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&sub) else {
            continue;
        };
        for f in files.flatten() {
            let name = f.file_name().to_string_lossy().to_string();
            for sid in sids {
                if name == format!("session_memory_{sid}.jsonl") {
                    return Some(project_dir.to_path_buf());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 落盘
// ---------------------------------------------------------------------------

/// 工具目录下的交接归档：`<工具目录>/trae/handoff/<clientKey>/<YYYYMMDD-HHMMSS>_<项目名>/`。
pub fn archive_dir(client_key: &str, project_name: &str) -> PathBuf {
    let mut safe: String = String::new();
    let mut last_underscore = false;
    for c in project_name.trim().chars() {
        if c.is_alphanumeric() || "._- ".contains(c) {
            safe.push(c);
            last_underscore = false;
        } else if !last_underscore {
            safe.push('_');
            last_underscore = true;
        }
    }
    let safe = if safe.trim().is_empty() {
        "project".to_string()
    } else {
        safe.trim().chars().take(40).collect()
    };
    let tag = Local::now().format("%Y%m%d-%H%M%S");
    store_dir().join("trae").join("handoff").join(client_key).join(format!("{tag}_{safe}"))
}

/// 原子写：先写临时文件再改名。
fn save_file(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content).map_err(|e| format!("写入失败：{e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("落盘失败：{e}"))?;
    Ok(())
}

/// 只追加（不覆盖）：文件不存在则新建；末尾已有换行则不再补。
fn append_line(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
    }
    let pre = std::fs::read_to_string(path).unwrap_or_default();
    let sep = if pre.is_empty() || pre.ends_with('\n') { "" } else { "\n" };
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("打开失败：{e}"))?;
    use std::io::Write;
    f.write_all(format!("{sep}{content}\n").as_bytes())
        .map_err(|e| format!("追加失败：{e}"))
}

/// 组装归档用的完整 JSON（含全部条目与原生记忆片段）。
fn archive_json(pkg: &HandoffPackage) -> Value {
    json!({
        "note": "Trae 原生记忆格式：topics.md 用 topicsLines；session_memory_<sid>.jsonl 每行一个 sessionMemory 元素；project_memory.md 用 projectMemory 三段。",
        "generatedAt": pkg.generated_at,
        "tool": "trae-switch-cn",
        "clientKey": pkg.client_key,
        "accountId": pkg.account_id,
        "projectPath": pkg.project_path,
        "projectName": pkg.project_name,
        "nextSteps": pkg.next_steps,
        "keyFiles": pkg.key_files,
        "noteText": pkg.note,
        "itemCount": pkg.items.len(),
        "totalItems": pkg.items.len() + pkg.dropped,
        "topicsLines": pkg.topics_lines,
        "sessionMemory": pkg.session_memory,
        "items": pkg.items,
    })
}

/// 预览交接：只组装、报告会写哪些文件，不落盘。
#[allow(clippy::too_many_arguments)]
pub fn handoff_preview(
    client_key: &str,
    project_path: Option<&str>,
    session_ids: Option<Vec<String>>,
    next_steps: Vec<String>,
    key_files: Vec<String>,
    note: Option<&str>,
) -> Result<Value, String> {
    let all_items = gather_items(client_key, session_ids.as_deref())?;
    let proj = project_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_default();
    let pkg = build_handoff(client_key, all_items.clone(), proj, None, None, next_steps, key_files, note);

    let mut files: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let project = Path::new(&pkg.project_path);
    if project.is_dir() {
        files.push(project.join(format!("{HANDOFF_FILE_PREFIX}.md")).to_string_lossy().to_string());
        files.push(
            project
                .join(".trae")
                .join("rules")
                .join(RULE_FILE_NAME)
                .to_string_lossy()
                .to_string(),
        );
    } else {
        skipped.push(format!("工作目录不可用，跳过项目目录/规则写入：{}", pkg.project_path));
    }

    // 记忆库 topics.md 落点（尽力而为）
    let memory_dir = if pkg.project_path.is_empty() {
        None
    } else {
        find_memory_project_dir(client_key, &pkg.project_path)
    };
    match &memory_dir {
        Some(dir) => {
            let ddir = Local::now().format("%Y%m%d").to_string();
            files.push(
                dir.join(&ddir)
                    .join("topics.md")
                    .to_string_lossy()
                    .to_string(),
            );
        }
        None => skipped.push("记忆库里没找到该项目的目录（不猜、不新建），跳过记忆库写入".to_string()),
    }

    let archive = archive_dir(client_key, &pkg.project_name);
    files.push(archive.join("HANDOFF.md").to_string_lossy().to_string());
    files.push(archive.join("memory-native.json").to_string_lossy().to_string());

    Ok(json!({
        "ok": true,
        "clientKey": client_key,
        "projectPath": pkg.project_path,
        "projectName": pkg.project_name,
        "itemCount": pkg.items.len(),
        "totalItems": all_items.len(),
        "markdown": pkg.markdown,
        "files": files,
        "skipped": skipped,
        "archiveDir": archive.to_string_lossy().to_string(),
    }))
}

/// 写入交接记忆：项目工作目录 + 项目规则 + Trae 记忆库 topics 追加 + 工具目录归档。
#[allow(clippy::too_many_arguments)]
pub fn handoff_write(
    client_key: &str,
    project_path: Option<&str>,
    session_ids: Option<Vec<String>>,
    next_steps: Vec<String>,
    key_files: Vec<String>,
    note: Option<&str>,
) -> Result<Value, String> {
    let all_items = gather_items(client_key, session_ids.as_deref())?;
    let proj = project_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_default();
    let pkg = build_handoff(client_key, all_items.clone(), proj, None, None, next_steps, key_files, note);

    let mut files: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut memory_files: Vec<String> = Vec::new();

    // ① 项目工作目录（磁盘路径，与账号无关）
    let project = Path::new(&pkg.project_path);
    let project_ok = project.is_dir();
    if project_ok {
        let target = project.join(format!("{HANDOFF_FILE_PREFIX}.md"));
        match save_file(&target, &pkg.markdown) {
            Ok(()) => files.push(target.to_string_lossy().to_string()),
            Err(e) => skipped.push(format!("{}（{e}）", target.to_string_lossy())),
        }
    } else {
        skipped.push(format!("工作目录不可用，跳过项目目录写入：{}", pkg.project_path));
    }

    // ①b 项目规则文件 `<项目>/.trae/rules/<RULE_FILE_NAME>`（每次对话注入 prompt，最可靠的一环）
    if project_ok {
        let target = project.join(".trae").join("rules").join(RULE_FILE_NAME);
        match save_file(&target, &pkg.rule_markdown) {
            Ok(()) => files.push(target.to_string_lossy().to_string()),
            Err(e) => skipped.push(format!("{}（{e}）", target.to_string_lossy())),
        }
    }

    // ② Trae 记忆库：只追加 topics.md（原生一行一条的格式）
    let memory_dir = if pkg.project_path.is_empty() {
        None
    } else {
        find_memory_project_dir(client_key, &pkg.project_path)
    };
    match &memory_dir {
        Some(dir) if !pkg.topics_lines.is_empty() => {
            let ddir = Local::now().format("%Y%m%d").to_string();
            let tp = dir.join(&ddir).join("topics.md");
            let block = format!(
                "\n<!-- trae-switch-cn handoff {} -->\n{}\n",
                pkg.generated_at,
                pkg.topics_lines.join("\n")
            );
            match append_line(&tp, &block) {
                Ok(()) => {
                    files.push(tp.to_string_lossy().to_string());
                    memory_files.push(tp.to_string_lossy().to_string());
                }
                Err(e) => skipped.push(format!("{}（{e}）", tp.to_string_lossy())),
            }
        }
        Some(_) => skipped.push("无交接条目，跳过记忆库写入".to_string()),
        None => skipped.push("记忆库里没找到该项目的目录（不猜、不新建），跳过记忆库写入".to_string()),
    }

    // ③ 工具目录归档（一定成功，且是完整一份）
    let archive = archive_dir(client_key, &pkg.project_name);
    let md_target = archive.join("HANDOFF.md");
    match save_file(&md_target, &pkg.markdown) {
        Ok(()) => files.push(md_target.to_string_lossy().to_string()),
        Err(e) => skipped.push(format!("{}（{e}）", md_target.to_string_lossy())),
    }
    let json_target = archive.join("memory-native.json");
    let content = serde_json::to_string_pretty(&archive_json(&pkg)).unwrap_or_default();
    match save_file(&json_target, &content) {
        Ok(()) => files.push(json_target.to_string_lossy().to_string()),
        Err(e) => skipped.push(format!("{}（{e}）", json_target.to_string_lossy())),
    }

    Ok(json!({
        "ok": true,
        "clientKey": client_key,
        "projectPath": pkg.project_path,
        "projectName": pkg.project_name,
        "itemCount": pkg.items.len(),
        "totalItems": all_items.len(),
        "files": files,
        "memoryFiles": memory_files,
        "skipped": skipped,
        "archiveDir": archive.to_string_lossy().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// 单测（纯函数，不触碰真实数据）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_collapses_and_caps() {
        assert_eq!(one_line("  a\n b\t c  ", 0), "a b c");
        assert_eq!(one_line("一二三四五", 3), "一二三…");
        assert_eq!(one_line("", 0), "");
    }

    #[test]
    fn norm_path_unifies_separators_and_case() {
        assert_eq!(norm_path(r"c:\Users\Foo\Bar"), "c:/users/foo/bar");
        assert_eq!(norm_path("c:/users//foo/bar/"), "c:/users/foo/bar");
    }

    #[test]
    fn summarize_tools_sorts_by_count() {
        let tools = vec!["read".into(), "edit".into(), "read".into(), "skill".into()];
        let got = summarize_tools(&tools);
        assert_eq!(got, vec!["read×2".to_string(), "edit×1".to_string(), "skill×1".to_string()]);
    }

    #[test]
    fn build_markdown_contains_key_sections() {
        let items = vec![HandoffItem {
            session_id: "0123456789abcdef0123".into(),
            title: "自动核算".into(),
            time: "2026-10-01 12:00:00".into(),
            intent: "写脚本".into(),
            actions: vec!["read×2".into()],
            outcome: "完成".into(),
            learned: vec![],
        }];
        let md = build_markdown(
            "proj",
            "d:/proj",
            "trae-cn",
            Some("u-1"),
            &items,
            0,
            &["继续优化".to_string()],
            &["main.py".to_string()],
            Some("备注"),
            "2026-10-02 10:00:00",
        );
        assert!(md.contains("TRAE_交接记忆 · proj"));
        assert!(md.contains("自动核算"));
        assert!(md.contains("写脚本"));
        assert!(md.contains("继续优化"));
        assert!(md.contains("main.py"));
        assert!(md.contains("备注"));
    }

    #[test]
    fn archive_dir_sanitizes_project_name() {
        let d = archive_dir("trae-cn", "a/b:c*?\"<>|\\ 项目名");
        let name = d.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.ends_with("_a_b_c_ 项目名"));
        assert_eq!(d.parent().unwrap().file_name().unwrap(), "trae-cn");
    }
}
