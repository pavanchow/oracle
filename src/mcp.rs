//! A Model Context Protocol (MCP) server so an AI agent can query attack paths
//! directly. Speaks JSON-RPC 2.0 over stdio (newline-delimited), no async needed.
//!
//! Tools exposed:
//!   oracle_query    run any OQL and get the structured result
//!   oracle_escalate escalation targets reachable from a principal
//!   oracle_graph    the loaded identity/network graph

use crate::Graph;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

enum Reply {
    Ok(Value),
    Err(i64, String),
    Silent,
}

pub fn serve_mcp(graph_path: &str) -> Result<()> {
    let raw = std::fs::read_to_string(graph_path)?;
    let graph = Graph::from_json(&raw)?;
    let graph_json: Value = serde_json::from_str(&raw)?;

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let reply = handle(&graph, &graph_json, method, req.get("params"));

        let envelope = match reply {
            Reply::Silent => continue,
            Reply::Ok(result) => match id {
                Some(id) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                None => continue, // response to a notification: nothing to send
            },
            Reply::Err(code, msg) => match id {
                Some(id) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }),
                None => continue,
            },
        };
        writeln!(stdout, "{envelope}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn handle(graph: &Graph, graph_json: &Value, method: &str, params: Option<&Value>) -> Reply {
    match method {
        "initialize" => Reply::Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "oracle", "version": env!("CARGO_PKG_VERSION") }
        })),
        "notifications/initialized" => Reply::Silent,
        "ping" => Reply::Ok(json!({})),
        "tools/list" => Reply::Ok(json!({ "tools": tool_list() })),
        "tools/call" => call_tool(graph, graph_json, params),
        _ => Reply::Err(-32601, format!("method not found: {method}")),
    }
}

fn tool_list() -> Value {
    json!([
        {
            "name": "oracle_query",
            "description": "Run an OQL query against the loaded identity/network graph and return the attack paths. OQL forms: PATHS FROM user(\"alice\") TO action(\"*\") | TO resource(\"x\") [VIA kind,...] [WITHIN n HOPS] [ON resource(\"arn\")]; ESCALATE FROM role(\"x\"); BLAST role(\"x\").",
            "inputSchema": {
                "type": "object",
                "properties": { "oql": { "type": "string", "description": "The OQL query." } },
                "required": ["oql"]
            }
        },
        {
            "name": "oracle_escalate",
            "description": "Privilege-escalation targets: identities this principal can reach by crossing a role-assumption or escalation-primitive boundary.",
            "inputSchema": {
                "type": "object",
                "properties": { "principal": { "type": "string", "description": "Node id, e.g. \"ci-runner\"." } },
                "required": ["principal"]
            }
        },
        {
            "name": "oracle_graph",
            "description": "Return the full loaded identity/network graph (nodes and edges) as JSON.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
}

fn call_tool(graph: &Graph, graph_json: &Value, params: Option<&Value>) -> Reply {
    let params = params.cloned().unwrap_or(json!({}));
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "oracle_query" => {
            let oql = args.get("oql").and_then(Value::as_str).unwrap_or("");
            match graph.run_oql(oql) {
                Ok(v) => text_result(&pretty(&v), false),
                Err(e) => text_result(&e.to_string(), true),
            }
        }
        "oracle_escalate" => {
            let principal = args.get("principal").and_then(Value::as_str).unwrap_or("");
            match graph.escalation_from(principal) {
                Ok(nodes) => {
                    let labels: Vec<String> =
                        nodes.into_iter().map(|n| graph.node_label(n)).collect();
                    text_result(&pretty(&json!({ "count": labels.len(), "targets": labels })), false)
                }
                Err(e) => text_result(&e.to_string(), true),
            }
        }
        "oracle_graph" => text_result(&pretty(graph_json), false),
        other => text_result(&format!("unknown tool: {other}"), true),
    }
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn text_result(text: &str, is_error: bool) -> Reply {
    Reply::Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_tool_returns_result() {
        let g = Graph::from_json(
            r#"{"nodes":[{"id":"a","kind":"user"},{"id":"b","kind":"role"}],
                "edges":[{"from":"a","to":"b","kind":"can_assume","action":"sts:AssumeRole"}]}"#,
        )
        .unwrap();
        let p = json!({ "name": "oracle_query", "arguments": { "oql": "ESCALATE FROM user(\"a\")" } });
        match call_tool(&g, &json!({}), Some(&p)) {
            Reply::Ok(v) => {
                assert_eq!(v["isError"], json!(false));
                assert!(v["content"][0]["text"].as_str().unwrap().contains("role:b"));
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn bad_oql_is_tool_error_not_protocol_error() {
        let g = Graph::from_json(r#"{"nodes":[],"edges":[]}"#).unwrap();
        let p = json!({ "name": "oracle_query", "arguments": { "oql": "NONSENSE" } });
        match call_tool(&g, &json!({}), Some(&p)) {
            Reply::Ok(v) => assert_eq!(v["isError"], json!(true)),
            _ => panic!("expected Ok with isError"),
        }
    }
}
