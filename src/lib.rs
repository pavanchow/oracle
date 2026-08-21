use anyhow::{bail, Context, Result};
use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use petgraph::visit::{Bfs, EdgeRef};
use petgraph::Direction::Outgoing;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

pub mod import_aws;
pub mod query;
pub mod server;
pub mod technique;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attrs: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: String,
    /// The IAM action granted, if any (e.g. `s3:GetObject`). Supports `*` globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The resource ARN the grant applies to, if any. Supports `*`/`?` globs.
    /// `None` means the grant is not resource-scoped (applies to any resource).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// IAM `Condition` block, captured verbatim so a path gated on MFA, source IP,
    /// etc. can be flagged conditional. The engine does not evaluate these yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Map<String, serde_json::Value>>,
}

/// The on-disk graph document: what the loader reads and the importer emits.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GraphDoc {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

impl GraphDoc {
    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// One hop in an attack path: the exact edge taken and the node it lands on.
#[derive(Debug, Clone, Copy)]
pub struct Step {
    pub edge: EdgeIndex,
    pub to: NodeIndex,
}

/// A concrete attack path: a start node and the edges walked from it.
#[derive(Debug, Clone)]
pub struct AttackPath {
    pub start: NodeIndex,
    pub steps: Vec<Step>,
}

impl AttackPath {
    pub fn hops(&self) -> usize {
        self.steps.len()
    }
}

/// Bounds on path search. Real attack paths are short, and enumeration is
/// exponential in the worst case, so both a depth and a result cap are enforced.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_depth: usize,
    pub max_results: usize,
    /// Hard cap on edges examined during a search. Simple-path enumeration is
    /// exponential in the worst case, so this bounds compute regardless of how
    /// dense the graph is. Hitting it sets `truncated`.
    pub max_visits: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 8,
            max_results: 1000,
            max_visits: 200_000,
        }
    }
}

pub struct PathSet {
    pub paths: Vec<AttackPath>,
    /// True if a cap was hit and some paths were not returned.
    pub truncated: bool,
}

/// An in-memory identity/network graph with unique-id lookup.
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
        let doc: GraphDoc = serde_json::from_str(text).context("parsing graph JSON")?;
        Graph::from_doc(doc)
    }

    pub fn from_doc(doc: GraphDoc) -> Result<Graph> {
        let mut g = DiGraph::<Node, Edge>::new();
        let mut index = HashMap::new();
        for n in doc.nodes {
            // Duplicate ids would silently resolve queries to the wrong node.
            if index.contains_key(&n.id) {
                bail!("duplicate node id `{}`", n.id);
            }
            let id = n.id.clone();
            let idx = g.add_node(n);
            index.insert(id, idx);
        }
        for e in doc.edges {
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

    /// Attack paths from one node to another, under the default limits.
    pub fn paths(&self, from: &str, to: &str) -> Result<PathSet> {
        self.paths_with(from, to, Limits::default(), &[])
    }

    /// Attack paths from one node to another, under explicit limits, optionally
    /// restricted to edges whose kind is in `via` (empty = any edge).
    pub fn paths_with(
        &self,
        from: &str,
        to: &str,
        limits: Limits,
        via: &[String],
    ) -> Result<PathSet> {
        let start = self.node_id(from)?;
        let target = self.node_id(to)?;
        let via: HashSet<String> = via.iter().cloned().collect();
        let mut out = Vec::new();
        let mut truncated = false;
        let mut visited = HashSet::new();
        let mut steps = Vec::new();
        let mut visits = 0usize;
        self.walk(
            start,
            start,
            target,
            &via,
            &mut visited,
            &mut steps,
            &mut out,
            &limits,
            &mut visits,
            &mut truncated,
        );
        Ok(PathSet {
            paths: out,
            truncated,
        })
    }

    /// Attack paths from a node to any capability whose granted action satisfies
    /// the pattern. A returned path always ENDS on the matching edge, so it truly
    /// grants the queried action (e.g. `action("*")` = who can reach full control).
    pub fn paths_to_action(&self, from: &str, pattern: &str) -> Result<PathSet> {
        self.paths_to_action_with(from, pattern, Limits::default(), &[], None)
    }

    /// As above, additionally restricting the matching edge to grants whose
    /// resource ARN matches `on_resource` (glob). `None` means any resource.
    pub fn paths_to_action_with(
        &self,
        from: &str,
        pattern: &str,
        limits: Limits,
        via: &[String],
        on_resource: Option<&str>,
    ) -> Result<PathSet> {
        let start = self.node_id(from)?;
        let via: HashSet<String> = via.iter().cloned().collect();
        // Prefix search is one hop shorter, since we append the matching edge.
        let plimits = Limits {
            max_depth: limits.max_depth.saturating_sub(1),
            max_results: limits.max_results,
            max_visits: limits.max_visits,
        };
        let mut out = Vec::new();
        let mut truncated = false;
        let mut visits = 0usize;
        for e in self.g.edge_indices() {
            if truncated {
                break;
            }
            let action = match &self.g[e].action {
                Some(a) => a,
                None => continue,
            };
            if !action_matches(pattern, action) {
                continue;
            }
            if !resource_ok(&self.g[e].resource, on_resource) {
                continue;
            }
            if !via.is_empty() && !via.contains(self.g[e].kind.as_str()) {
                continue;
            }
            let (u, v) = match self.g.edge_endpoints(e) {
                Some(pair) => pair,
                None => continue,
            };
            if v == start {
                continue;
            }
            if u == start {
                out.push(AttackPath {
                    start,
                    steps: vec![Step { edge: e, to: v }],
                });
                if out.len() >= limits.max_results {
                    truncated = true;
                }
                continue;
            }
            // Every simple path start -> u, then the matching edge u -> v appended.
            let mut prefixes = Vec::new();
            let mut visited = HashSet::new();
            let mut steps = Vec::new();
            let mut ptrunc = false;
            self.walk(
                start, start, u, &via, &mut visited, &mut steps, &mut prefixes, &plimits,
                &mut visits, &mut ptrunc,
            );
            if ptrunc {
                truncated = true;
            }
            for p in prefixes {
                // Keep the whole path simple: v must be new.
                if v == start || p.steps.iter().any(|s| s.to == v) {
                    continue;
                }
                let mut steps2 = p.steps.clone();
                steps2.push(Step { edge: e, to: v });
                out.push(AttackPath {
                    start,
                    steps: steps2,
                });
                if out.len() >= limits.max_results {
                    truncated = true;
                    break;
                }
            }
        }
        Ok(PathSet {
            paths: out,
            truncated,
        })
    }

    /// Identities reachable via a path that crosses a privilege boundary, i.e.
    /// that traverses at least one `can_assume` edge. Plain reachability to your
    /// own group is not escalation, so this is not just a filtered `BLAST`.
    pub fn escalation_from(&self, from: &str) -> Result<Vec<NodeIndex>> {
        let start = self.node_id(from)?;
        // BFS over (node, crossed_a_boundary) states.
        let mut seen: HashSet<(NodeIndex, bool)> = HashSet::new();
        let mut emitted: HashSet<NodeIndex> = HashSet::new();
        let mut q = VecDeque::new();
        let mut out = Vec::new();
        seen.insert((start, false));
        q.push_back((start, false));
        while let Some((cur, crossed)) = q.pop_front() {
            for e in self.g.edges_directed(cur, Outgoing) {
                let next = e.target();
                let ncross = crossed || e.weight().kind == "can_assume";
                if seen.insert((next, ncross)) {
                    if ncross
                        && next != start
                        && matches!(self.node_kind_of(next), "user" | "group" | "role")
                        && emitted.insert(next)
                    {
                        out.push(next);
                    }
                    q.push_back((next, ncross));
                }
            }
        }
        Ok(out)
    }

    /// Every node reachable from a start node (bounded, one visit per node).
    pub fn reachable_from(&self, from: &str) -> Result<Vec<NodeIndex>> {
        let start = self.node_id(from)?;
        let mut bfs = Bfs::new(&self.g, start);
        let mut out = Vec::new();
        while let Some(nx) = bfs.next(&self.g) {
            if nx != start {
                out.push(nx);
            }
        }
        Ok(out)
    }

    pub fn node_label(&self, idx: NodeIndex) -> String {
        let n = &self.g[idx];
        format!("{}:{}", n.kind, n.id)
    }

    pub fn node_kind_of(&self, idx: NodeIndex) -> &str {
        &self.g[idx].kind
    }

    pub fn node_id_of(&self, idx: NodeIndex) -> &str {
        &self.g[idx].id
    }

    /// Actions this node grants directly (its outgoing `has_permission` edges).
    pub fn granted_actions(&self, idx: NodeIndex) -> Vec<&str> {
        self.g
            .edges_directed(idx, Outgoing)
            .filter(|e| e.weight().kind == "has_permission")
            .filter_map(|e| e.weight().action.as_deref())
            .collect()
    }

    /// Every principal (user/group/role) an attacker gains along a path: the
    /// start plus each identity landed on. Techniques reason over these.
    pub fn path_principals(&self, p: &AttackPath) -> Vec<NodeIndex> {
        let is_principal = |k: &str| matches!(k, "user" | "group" | "role");
        let mut out = Vec::new();
        if is_principal(self.node_kind_of(p.start)) {
            out.push(p.start);
        }
        for s in &p.steps {
            if is_principal(self.node_kind_of(s.to)) {
                out.push(s.to);
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// One attack path as a JSON value: a start node, edge-labeled hops, and any
    /// exploit techniques the path confers.
    pub fn path_json(&self, p: &AttackPath) -> serde_json::Value {
        let hops: Vec<serde_json::Value> = p
            .steps
            .iter()
            .map(|s| {
                let e = &self.g[s.edge];
                serde_json::json!({
                    "edge": e.kind,
                    "action": e.action,
                    "resource": e.resource,
                    "conditional": e.conditions.as_ref().is_some_and(|c| !c.is_empty()),
                    "to": self.node_label(s.to),
                })
            })
            .collect();
        serde_json::json!({
            "start": self.node_label(p.start),
            "hops": hops,
            "techniques": crate::technique::detect(self, p),
        })
    }

    /// Parse and run an OQL query, returning a structured JSON result. Shared by
    /// the CLI (`--json`) and the HTTP API.
    pub fn run_oql(&self, oql: &str) -> Result<serde_json::Value> {
        use crate::query::{parse, Query, Target};
        Ok(match parse(oql)? {
            Query::Paths {
                from_id,
                to,
                via,
                within,
                on_resource,
                ..
            } => {
                let mut limits = Limits::default();
                if let Some(h) = within {
                    limits.max_depth = h;
                }
                let r = match to {
                    Target::Node { id, .. } => self.paths_with(&from_id, &id, limits, &via)?,
                    Target::Action(pat) => self.paths_to_action_with(
                        &from_id,
                        &pat,
                        limits,
                        &via,
                        on_resource.as_deref(),
                    )?,
                };
                serde_json::json!({
                    "kind": "paths",
                    "count": r.paths.len(),
                    "truncated": r.truncated,
                    "paths": r.paths.iter().map(|p| self.path_json(p)).collect::<Vec<_>>(),
                })
            }
            Query::Escalate { from_id, .. } => {
                let nodes: Vec<String> = self
                    .escalation_from(&from_id)?
                    .into_iter()
                    .map(|n| self.node_label(n))
                    .collect();
                serde_json::json!({ "kind": "escalation", "count": nodes.len(), "nodes": nodes })
            }
            Query::Blast { from_id, .. } => {
                let nodes: Vec<String> = self
                    .reachable_from(&from_id)?
                    .into_iter()
                    .map(|n| self.node_label(n))
                    .collect();
                serde_json::json!({ "kind": "reach", "count": nodes.len(), "nodes": nodes })
            }
        })
    }

    /// Render one attack path, showing the exact edge that enabled each hop and
    /// flagging any hop that is gated by an IAM condition.
    pub fn render_path(&self, p: &AttackPath) -> String {
        let mut out = self.node_label(p.start);
        for s in &p.steps {
            let ed = &self.g[s.edge];
            let mut label = match &ed.action {
                Some(a) => format!("{} {}", ed.kind, a),
                None => ed.kind.clone(),
            };
            if let Some(res) = &ed.resource {
                label.push_str(&format!(" on {res}"));
            }
            if let Some(cond) = &ed.conditions {
                if !cond.is_empty() {
                    let keys: Vec<&str> = cond.keys().map(String::as_str).collect();
                    label.push_str(&format!(" (conditional: {})", keys.join(", ")));
                }
            }
            out.push_str(&format!(" --[{}]--> {}", label, self.node_label(s.to)));
        }
        out
    }

    /// Depth-first enumeration of simple paths that carries the exact edge for
    /// each hop (so parallel edges stay distinct) and honors both caps.
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        start: NodeIndex,
        cur: NodeIndex,
        target: NodeIndex,
        via: &HashSet<String>,
        visited: &mut HashSet<NodeIndex>,
        steps: &mut Vec<Step>,
        out: &mut Vec<AttackPath>,
        limits: &Limits,
        visits: &mut usize,
        truncated: &mut bool,
    ) {
        if out.len() >= limits.max_results {
            *truncated = true;
            return;
        }
        if steps.len() >= limits.max_depth {
            return;
        }
        for e in self.g.edges_directed(cur, Outgoing) {
            // Bound total work so a dense graph cannot pin the CPU.
            *visits += 1;
            if *visits > limits.max_visits {
                *truncated = true;
                return;
            }
            // Restrict to allowed edge kinds when a VIA filter is set.
            if !via.is_empty() && !via.contains(e.weight().kind.as_str()) {
                continue;
            }
            let next = e.target();
            // Simple paths only: never revisit the start or an in-path node.
            if next == start || visited.contains(&next) {
                continue;
            }
            steps.push(Step {
                edge: e.id(),
                to: next,
            });
            if next == target {
                out.push(AttackPath {
                    start,
                    steps: steps.clone(),
                });
                if out.len() >= limits.max_results {
                    *truncated = true;
                    steps.pop();
                    return;
                }
            } else {
                visited.insert(next);
                self.walk(
                    start, next, target, via, visited, steps, out, limits, visits, truncated,
                );
                visited.remove(&next);
            }
            steps.pop();
        }
    }
}

/// Does an edge granting `grant` satisfy a query for `query`? Both sides may use
/// a trailing `*`. A `*` grant covers any queried action; `s3:*` covers `s3:X`.
pub fn action_matches(query: &str, grant: &str) -> bool {
    if query == "*" {
        return true;
    }
    if let Some(qpfx) = query.strip_suffix('*') {
        return grant.starts_with(qpfx)
            || grant == "*"
            || grant
                .strip_suffix('*')
                .is_some_and(|gpfx| qpfx.starts_with(gpfx));
    }
    if grant == query || grant == "*" {
        return true;
    }
    if let Some(gpfx) = grant.strip_suffix('*') {
        return query.starts_with(gpfx);
    }
    false
}

/// Does an edge's resource grant satisfy a queried resource ARN? A grant of
/// `None` is unscoped and covers any resource. Both sides may glob.
fn resource_ok(edge_resource: &Option<String>, query: Option<&str>) -> bool {
    match (edge_resource, query) {
        (_, None) => true,
        (None, Some(_)) => true,
        (Some(grant), Some(q)) => wildcard_match(grant, q) || wildcard_match(q, grant),
    }
}

/// Glob match supporting `*` (any run, including empty) and `?` (one char),
/// the wildcards IAM resource ARNs use.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while j < t.len() {
        if i < p.len() && (p[i] == '?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // alice -can_assume-> admin -has_permission *-> all
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
        let r = g.paths("alice", "all").unwrap();
        assert_eq!(r.paths.len(), 1);
        assert_eq!(r.paths[0].hops(), 2);
        assert!(!r.truncated);
    }

    #[test]
    fn no_path_when_unreachable() {
        let g = Graph::from_json(SAMPLE).unwrap();
        assert!(g.paths("all", "alice").unwrap().paths.is_empty());
    }

    #[test]
    fn unknown_node_errors() {
        let g = Graph::from_json(SAMPLE).unwrap();
        assert!(g.paths("nope", "all").is_err());
    }

    #[test]
    fn rejects_duplicate_ids() {
        let j = r#"{"nodes":[{"id":"x","kind":"user"},{"id":"x","kind":"role"}],"edges":[]}"#;
        assert!(Graph::from_json(j).is_err());
    }

    #[test]
    fn parallel_edges_render_distinctly() {
        let j = r#"{
            "nodes":[{"id":"a","kind":"user"},{"id":"b","kind":"role"}],
            "edges":[
                {"from":"a","to":"b","kind":"can_assume","action":"sts:AssumeRole"},
                {"from":"a","to":"b","kind":"trusts","action":"cross-account"}
            ]}"#;
        let g = Graph::from_json(j).unwrap();
        let r = g.paths("a", "b").unwrap();
        assert_eq!(r.paths.len(), 2);
        let rendered: Vec<String> = r.paths.iter().map(|p| g.render_path(p)).collect();
        assert!(rendered.iter().any(|s| s.contains("can_assume")));
        assert!(rendered.iter().any(|s| s.contains("trusts")));
        assert_ne!(rendered[0], rendered[1]);
    }

    #[test]
    fn respects_max_depth() {
        let j = r#"{
            "nodes":[{"id":"a","kind":"user"},{"id":"b","kind":"role"},
                     {"id":"c","kind":"role"},{"id":"d","kind":"resource"}],
            "edges":[{"from":"a","to":"b","kind":"x"},
                     {"from":"b","to":"c","kind":"x"},
                     {"from":"c","to":"d","kind":"x"}]}"#;
        let g = Graph::from_json(j).unwrap();
        let shallow = g
            .paths_with("a", "d", Limits { max_depth: 2, ..Limits::default() }, &[])
            .unwrap();
        assert!(shallow.paths.is_empty());
        let deep = g
            .paths_with("a", "d", Limits { max_depth: 8, ..Limits::default() }, &[])
            .unwrap();
        assert_eq!(deep.paths.len(), 1);
        assert_eq!(deep.paths[0].hops(), 3);
    }

    #[test]
    fn cap_sets_truncated() {
        let j = r#"{
            "nodes":[{"id":"a","kind":"user"},{"id":"b","kind":"role"}],
            "edges":[{"from":"a","to":"b","kind":"x"},{"from":"a","to":"b","kind":"y"}]}"#;
        let g = Graph::from_json(j).unwrap();
        let r = g
            .paths_with("a", "b", Limits { max_depth: 8, max_results: 1, ..Limits::default() }, &[])
            .unwrap();
        assert_eq!(r.paths.len(), 1);
        assert!(r.truncated);
    }

    #[test]
    fn visit_budget_bounds_work() {
        // A dense graph; a tiny visit budget must stop early and flag truncation.
        let mut nodes = String::new();
        let mut edges = String::new();
        for i in 0..12 {
            nodes.push_str(&format!("{{\"id\":\"n{i}\",\"kind\":\"role\"}},"));
            for j in 0..12 {
                if i != j {
                    edges.push_str(&format!("{{\"from\":\"n{i}\",\"to\":\"n{j}\",\"kind\":\"x\"}},"));
                }
            }
        }
        let json = format!("{{\"nodes\":[{}],\"edges\":[{}]}}", nodes.trim_end_matches(','), edges.trim_end_matches(','));
        let g = Graph::from_json(&json).unwrap();
        let r = g
            .paths_with("n0", "n11", Limits { max_visits: 100, ..Limits::default() }, &[])
            .unwrap();
        assert!(r.truncated);
    }

    #[test]
    fn via_restricts_edge_kinds() {
        // a -can_assume-> b -network-> c ; VIA can_assume must not reach c.
        let j = r#"{
            "nodes":[{"id":"a","kind":"user"},{"id":"b","kind":"role"},{"id":"c","kind":"resource"}],
            "edges":[{"from":"a","to":"b","kind":"can_assume"},
                     {"from":"b","to":"c","kind":"network"}]}"#;
        let g = Graph::from_json(j).unwrap();
        let all = g
            .paths_with("a", "c", Limits::default(), &[])
            .unwrap();
        assert_eq!(all.paths.len(), 1);
        let restricted = g
            .paths_with("a", "c", Limits::default(), &["can_assume".into()])
            .unwrap();
        assert!(restricted.paths.is_empty());
    }

    #[test]
    fn action_query_final_edge_must_match() {
        // alice reaches b only via a non-matching edge; c reaches b via s3:PutObject.
        // action("s3:*") from alice must return NOTHING (the earlier bug returned a
        // path to b labeled by the wrong edge).
        let j = r#"{
            "nodes":[{"id":"alice","kind":"user"},{"id":"c","kind":"role"},{"id":"b","kind":"resource"}],
            "edges":[{"from":"alice","to":"b","kind":"has_permission","action":"logs:Get"},
                     {"from":"c","to":"b","kind":"has_permission","action":"s3:PutObject"}]}"#;
        let g = Graph::from_json(j).unwrap();
        assert!(g.paths_to_action("alice", "s3:*").unwrap().paths.is_empty());
        // From c it is real, and the final edge is the matching one.
        let r = g.paths_to_action("c", "s3:*").unwrap();
        assert_eq!(r.paths.len(), 1);
        assert!(g.render_path(&r.paths[0]).contains("s3:PutObject"));
    }

    #[test]
    fn action_query_picks_the_matching_parallel_edge() {
        // Two parallel edges alice->b; only one grants s3. Must return exactly the
        // matching one, not both, and not the logs edge.
        let j = r#"{
            "nodes":[{"id":"alice","kind":"user"},{"id":"b","kind":"resource"}],
            "edges":[{"from":"alice","to":"b","kind":"has_permission","action":"s3:PutObject"},
                     {"from":"alice","to":"b","kind":"has_permission","action":"logs:Get"}]}"#;
        let g = Graph::from_json(j).unwrap();
        let r = g.paths_to_action("alice", "s3:*").unwrap();
        assert_eq!(r.paths.len(), 1);
        let rendered = g.render_path(&r.paths[0]);
        assert!(rendered.contains("s3:PutObject"));
        assert!(!rendered.contains("logs:Get"));
    }

    #[test]
    fn no_self_path_for_same_node() {
        let j = r#"{
            "nodes":[{"id":"a","kind":"user"},{"id":"b","kind":"role"}],
            "edges":[{"from":"a","to":"a","kind":"member_of"},
                     {"from":"a","to":"b","kind":"x"},
                     {"from":"b","to":"a","kind":"x"}]}"#;
        let g = Graph::from_json(j).unwrap();
        assert!(g.paths("a", "a").unwrap().paths.is_empty());
    }

    #[test]
    fn escalation_requires_boundary_crossing() {
        let g = Graph::load("data/worked-examples.json").unwrap();
        // ci-runner assumes deployer (a can_assume boundary), reaching deployer
        // and admin. Both are real escalations.
        let esc: Vec<String> = g
            .escalation_from("ci-runner")
            .unwrap()
            .into_iter()
            .map(|n| g.node_label(n))
            .collect();
        assert!(esc.iter().any(|s| s == "role:deployer"));
        assert!(esc.iter().any(|s| s == "role:admin"));
        // contractor only has member_of into its own group. That is not escalation.
        assert!(g.escalation_from("contractor").unwrap().is_empty());
    }

    #[test]
    fn action_glob_matches() {
        assert!(action_matches("s3:GetObject", "*"));
        assert!(action_matches("s3:GetObject", "s3:*"));
        assert!(action_matches("s3:*", "s3:GetObject"));
        assert!(action_matches("*", "iam:PassRole"));
        assert!(!action_matches("s3:GetObject", "ec2:*"));
    }

    #[test]
    fn wildcard_matches_arns() {
        assert!(wildcard_match("arn:aws:s3:::prod/*", "arn:aws:s3:::prod/data.csv"));
        assert!(wildcard_match("arn:aws:*", "arn:aws:iam::1:role/admin"));
        assert!(wildcard_match("arn:aws:s3:::p?od", "arn:aws:s3:::prod"));
        assert!(!wildcard_match("arn:aws:s3:::prod/*", "arn:aws:s3:::other/x"));
        assert!(wildcard_match("exact", "exact"));
        assert!(!wildcard_match("exact", "exacter"));
    }

    #[test]
    fn resource_ok_semantics() {
        assert!(resource_ok(&None, Some("anything"))); // unscoped grant covers all
        assert!(resource_ok(&Some("arn:aws:s3:::b/*".into()), None)); // no query = match
        assert!(resource_ok(
            &Some("arn:aws:s3:::b/*".into()),
            Some("arn:aws:s3:::b/key")
        ));
        assert!(!resource_ok(
            &Some("arn:aws:s3:::b/*".into()),
            Some("arn:aws:s3:::c/key")
        ));
    }

    #[test]
    fn action_query_filters_by_resource() {
        let j = r#"{
            "nodes":[{"id":"a","kind":"user"},{"id":"b","kind":"resource"},{"id":"c","kind":"resource"}],
            "edges":[
                {"from":"a","to":"b","kind":"has_permission","action":"s3:GetObject","resource":"arn:aws:s3:::mine/*"},
                {"from":"a","to":"c","kind":"has_permission","action":"s3:GetObject","resource":"arn:aws:s3:::yours/*"}
            ]}"#;
        let g = Graph::from_json(j).unwrap();
        let any = g.paths_to_action("a", "s3:*").unwrap();
        assert_eq!(any.paths.len(), 2);
        let scoped = g
            .paths_to_action_with(
                "a",
                "s3:*",
                Limits::default(),
                &[],
                Some("arn:aws:s3:::mine/secret"),
            )
            .unwrap();
        assert_eq!(scoped.paths.len(), 1);
        assert!(g.render_path(&scoped.paths[0]).contains("mine"));
    }

    #[test]
    fn conditional_edge_is_flagged_and_arns_render() {
        let g = Graph::load("data/iam-sample.json").unwrap();
        let r = g.paths_to_action("alice", "s3:PutObject").unwrap();
        // The direct s3:PutObject grant is one path; a `*` admin grant is another.
        // The direct one must be flagged conditional and carry the ARN.
        let direct = r
            .paths
            .iter()
            .map(|p| g.render_path(p))
            .find(|s| s.contains("s3:PutObject"))
            .expect("expected a direct s3:PutObject path");
        assert!(direct.contains("conditional: aws:MultiFactorAuthPresent"));
        assert!(direct.contains("arn:aws:s3:::prod-artifacts/*"));
    }

    #[test]
    fn and_bundle_reaches_full_control() {
        let g = Graph::load("data/iam-sample.json").unwrap();
        let r = g.paths_to_action("alice", "*").unwrap();
        assert!(r
            .paths
            .iter()
            .any(|p| g.render_path(p).contains("lambda-passrole-escalation")));
    }
}
