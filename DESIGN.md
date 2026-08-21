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

## Roadmap

1. Foundation (this slice): graph model, JSON loader, path enumeration, CLI.
2. OQL parser with `chumsky`, real query surface.
3. Escalation and blast-radius queries, edge conditions.
4. AWS IAM importer.
5. axum API, then the graph visualization UI.
6. MCP server for agent access.

## Data format

A graph is one JSON object:

```json
{
  "nodes": [{ "id": "alice", "kind": "user" }],
  "edges": [{ "from": "alice", "to": "developers", "kind": "member_of" }]
}
```

`nodes[].attrs` and `edges[].action` are optional. See `data/sample-graph.json`.
