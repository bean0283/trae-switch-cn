use rusqlite::Connection;

fn main() {
    let db = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: inspect_db <db>");
        std::process::exit(2);
    });
    let conn = Connection::open(&db).expect("open");
    let mut stmt = conn
        .prepare("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name")
        .expect("list tables");
    let mut tables = Vec::new();
    for r in stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .expect("query")
    {
        let (name, sql) = r.expect("row");
        tables.push((name, sql));
    }
    let want = [
        "chat_session",
        "session_project",
        "chat_turn",
        "agent_run",
        "chat_message",
        "project",
        "checkpoint",
        "core_memory",
        "session_agent_relation",
        "mcp_server_agent_relation",
        "agent_member_relation",
    ];
    for w in want {
        let hit = tables.iter().find(|(n, _)| n == w);
        match hit {
            Some((_, Some(sql))) => {
                let first = sql.lines().next().unwrap_or("").to_string();
                println!("== {w} ==\n{first}");
                let cols = sql
                    .lines()
                    .filter(|l| l.trim_start().starts_with('"') || l.trim_start().starts_with('`'))
                    .map(|l| l.trim().trim_end_matches(',').to_string())
                    .collect::<Vec<_>>();
                for c in cols {
                    println!("    {c}");
                }
            }
            _ => println!("== {w} ==  (NOT FOUND)"),
        }
    }
    // chat_session user_id 是否存在
    let cs_sql = tables.iter().find(|(n, _)| n == "chat_session");
    if let Some((_, Some(sql))) = cs_sql {
        let has_uid = sql.contains("user_id");
        println!("chat_session has user_id column: {has_uid}");
    }
}
