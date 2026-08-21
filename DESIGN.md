# Oracle, design

Oracle is a query language whose result is an attack path across an identity and
network graph, not a set of rows. You ask "how can this principal reach that
capability" and Oracle returns the concrete chains of permissions and trust that
get them there.

## Prior art, and where Oracle differs

- **BloodHound** maps Active Directory attack paths in a Neo4j graph. Powerful,
  but AD-specific and driven by raw Cypher.
- **PMapper** models AWS IAM as a graph and answers reachability in Python.
- **Cartography / Cloudmapper / Prowler** inventory cloud assets and flag
  misconfigurations. They map *what exists*, not *what an attacker can chain*.
- **Neo4j + Cypher** is a general graph query language. Attack paths are
  expressible but not first class; you hand-write traversals every time.

Oracle's difference: the attack path is the primitive. The language has path
semantics built in (reachability, escalation, blast radius), the model is
cloud-and-network native, and every query returns a walkable chain with the
permission or trust edge that made each hop possible.

## Graph model

Nodes carry a `kind` and an `id`:

- `user`, `group`, `role`, `service` (principals and identities)
- `resource` (buckets, functions, hosts, secrets)

Edges carry a `kind` and an optional `action`:

- `member_of` (user to group)
- `can_assume` (principal to role, e.g. `sts:AssumeRole`)
- `has_permission` (principal to resource or role, with the action granted)
- `trusts` (cross-account or cross-domain trust)
- `network` (reachability between hosts)

An attack path is a directed walk from a starting principal to a target
capability, where each edge is a permission or trust the attacker can exercise.

## Query language (OQL), first sketch

Two entry shapes:

```
PATHS FROM user("alice") TO resource("prod-artifacts")
PATHS FROM user("alice") TO action("*")            -- who can reach full control
ESCALATE FROM user("alice")                         -- reachable roles above start
BLAST role("deployer")                              -- everything this role reaches
```

The grammar will be built with `chumsky` (or `tree-sitter` for editor tooling).
The foundation ships the engine and a CLI surface; the parser is the next slice.

## Architecture

- **Rust core.** Single static binary via cargo.
- **Graph engine:** `petgraph`, in-memory directed graph, simple-path enumeration.
- **Model + loading:** `serde` over a portable JSON graph format, so we build and
  test on synthetic data with no live cloud credentials.
- **Storage (later):** `sled` or `sqlite` for large graphs.
- **UI (later):** `axum` API plus a graph visualization designed in Claude Design.
- **MCP server (later):** expose Oracle so agents can query attack paths directly.
- **Importers (later):** AWS IAM, then GCP and network sources, into the JSON model.

## Query language (OQL v2)

```
PATHS FROM user("alice") TO resource("prod")
PATHS FROM user("alice") TO action("s3:*")
PATHS FROM user("alice") TO action("*") VIA can_assume, has_permission WITHIN 4 HOPS
ESCALATE FROM user("alice")
BLAST role("deployer")
```

- `VIA <kind>[, <kind>...]` restricts traversal to those edge kinds.
- `WITHIN n HOPS` caps path length in the language (not just the CLI default).
- `action("P")` returns paths that END on an edge whose grant satisfies `P` under
  glob (`*`, `s3:*`, exact). The final hop always grants the queried action, so a
  path can never be mislabeled with an action it does not actually confer.
- `ESCALATE` returns every reachable identity (user, group, role), since real
  privilege escalation loops back through users and groups, not only roles.

## Roadmap

1. Foundation (done): graph model, JSON loader, edge-aware bounded path engine, CLI.
2. OQL parser (done): hand-written lexer + recursive descent. `PATHS`, `ESCALATE`,
   `BLAST`, node and `action(...)` targets, `VIA` edge filter, `WITHIN n HOPS`.
3. AWS IAM importer into the JSON model (see model decisions below).
4. axum API, then the graph visualization UI.
5. MCP server for agent access.

## IAM model (implemented, ready for the importer)

The model was extended before writing the importer so it is right from the start.
`data/iam-sample.json` exercises all of it.

- **Resource ARN globbing (done).** `Edge.resource: Option<String>` carries the ARN
  a grant applies to. `wildcard_match` handles `*` and `?` as IAM does. OQL gained
  `ON resource("arn")` to scope an `action(...)` query. `None` means unscoped (any
  resource).
- **Condition keys (done).** `Edge.conditions` captures the IAM `Condition` block
  verbatim. The engine does not evaluate them yet, but any hop gated by a condition is
  rendered `(conditional: <keys>)`, so an MFA- or IP-gated path is never reported as a
  clean win. That avoids false positives.
- **AND-logic via bundle nodes (Option B, done).** Some escalations need multiple
  grants at once (`lambda:UpdateFunctionCode` AND `iam:PassRole`). A plain directed
  edge is OR-logic, so AND is resolved at import time: the importer creates a
  `kind: "bundle"` node (with `attrs.requires` listing the actions) and only links a
  principal into it when the principal holds all required grants. Traversing the bundle
  then implies acquiring the whole technique. The graph engine stays simple.
- **Policies as first-class nodes.** Policies stay `kind: "policy"` rather than being
  flattened, so paths read `user -> policy -> resource` and keep remediation context
  (revoke *this* policy).

## What the importer does next

Consume `aws iam get-account-authorization-details` (works offline on a saved export),
and emit this graph JSON: principals as nodes, attached and inline policies expanded
into `has_permission` edges with `action`/`resource`/`conditions`, `sts:AssumeRole`
trust into `can_assume` edges, and known escalation techniques into bundle nodes.

## Safety and correctness notes

- Node ids must be unique; the loader rejects duplicates (a duplicate would
  silently resolve a query to the wrong node, a false negative on a security graph).
- Path search is bounded by `Limits { max_depth, max_results }` (default 8 hops,
  1000 results) and reports `truncated` when a cap is hit. Simple-path enumeration
  is exponential in the worst case, so unbounded search is a DoS vector, especially
  once the HTTP API and MCP server ship.
- Paths carry the exact edge taken per hop, so parallel edges (a principal that can
  both `can_assume` and `has_permission` on the same role) stay distinct.
- `action(...)` paths end on the matching edge, so the reported path genuinely
  grants the queried action.

## Data format

A graph is one JSON object:

```json
{
  "nodes": [{ "id": "alice", "kind": "user" }],
  "edges": [{ "from": "alice", "to": "developers", "kind": "member_of" }]
}
```

`nodes[].attrs` and `edges[].action` are optional. See `data/sample-graph.json`.
