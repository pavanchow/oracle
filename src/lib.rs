use anyhow::{Context, Result};
use petgraph::algo::all_simple_paths;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub attrs: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: String,
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawGraph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

/// An in-memory identity/network graph with id lookup.
pub struct Graph {
    g: DiGraph<Node, Edge>,
    index: HashMap<String, NodeIndex>,
}

impl Graph {
    pub fn load(path: &str) -> Result<Graph> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading graph file {path}"))?;
        Graph::from_json(&text)
    }

    pub fn from_json(text: &str) -> Result<Graph> {
        let raw: RawGraph = serde_json::from_str(text).context("parsing graph JSON")?;
        let mut g = DiGraph::<Node, Edge>::new();
        let mut index = HashMap::new();
        for n in raw.nodes {
            let id = n.id.clone();
            let idx = g.add_node(n);
            index.insert(id, idx);
        }
        for e in raw.edges {
            let from = *index
                .get(&e.from)
                .with_context(|| format!("edge references unknown node {}", e.from))?;
            let to = *index
                .get(&e.to)
                .with_context(|| format!("edge references unknown node {}", e.to))?;
            g.add_edge(from, to, e);
        }
        Ok(Graph { g, index })
    }

    fn node_id(&self, id: &str) -> Result<NodeIndex> {
        self.index
            .get(id)
            .copied()
            .with_context(|| format!("no node with id {id}"))
    }

    /// Every simple attack path from one node to another.
    pub fn paths(&self, from: &str, to: &str) -> Result<Vec<Vec<NodeIndex>>> {
        let a = self.node_id(from)?;
        let b = self.node_id(to)?;
        Ok(all_simple_paths::<Vec<_>, _>(&self.g, a, b, 0, None).collect())
    }

    /// Render one path as a readable chain with the edge that enabled each hop.
    pub fn render_path(&self, path: &[NodeIndex]) -> String {
        if path.is_empty() {
            return String::new();
        }
        let label = |idx: NodeIndex| {
            let n = &self.g[idx];
            format!("{}:{}", n.kind, n.id)
        };
        let mut out = label(path[0]);
        for w in path.windows(2) {
            let edge = self.g.find_edge(w[0], w[1]).map(|e| {
                let ed = &self.g[e];
                match &ed.action {
                    Some(a) => format!("{} {}", ed.kind, a),
                    None => ed.kind.clone(),
                }
            });
            out.push_str(&format!(" --[{}]--> {}", edge.unwrap_or_default(), label(w[1])));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "nodes": [
            {"id": "alice", "kind": "user"},
            {"id": "admin", "kind": "role"},
            {"id": "all", "kind": "resource"}
        ],
        "edges": [
            {"from": "alice", "to": "admin", "kind": "can_assume", "action": "sts:AssumeRole"},
            {"from": "admin", "to": "all", "kind": "has_permission", "action": "*"}
        ]
    }"#;

    #[test]
    fn finds_the_escalation_path() {
        let g = Graph::from_json(SAMPLE).unwrap();
        let paths = g.paths("alice", "all").unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 3);
    }

    #[test]
    fn no_path_when_unreachable() {
        let g = Graph::from_json(SAMPLE).unwrap();
        let paths = g.paths("all", "alice").unwrap();
        assert!(paths.is_empty());
    }
}
