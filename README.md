# Oracle

A query language whose results are attack paths across identity and network graphs rather than plain rows, aimed at surfacing privilege escalation and lateral movement.

You ask how a principal can reach a capability, and Oracle returns the concrete chains of permissions and trust that get them there. See [DESIGN.md](DESIGN.md) for the model, the query language, and the roadmap.

## Build

```
cargo build
cargo test
```

## Try it

The repo ships a synthetic identity graph in `data/sample-graph.json`.

Query it in OQL, the Oracle Query Language:

```
cargo run -- query 'PATHS FROM user("alice") TO action("*")'
cargo run -- query 'PATHS FROM user("alice") TO resource("prod-artifacts")'
cargo run -- query 'ESCALATE FROM user("alice")'
cargo run -- query 'BLAST role("deployer")'
```

Example output:

```
[1] user:alice --[member_of]--> group:developers --[can_assume sts:AssumeRole]-->
    role:build-runner --[can_assume sts:AssumeRole]--> role:deployer
    --[has_permission iam:PutRolePolicy]--> role:admin --[has_permission *]-->
    resource:all-resources
```

The raw path command is still there: `cargo run -- paths --from alice --to all-resources`.

## Import a real AWS account

Point Oracle at a live account by feeding it the IAM authorization details:

```
aws iam get-account-authorization-details > authdetails.json
cargo run -- import-aws --input authdetails.json --output aws-graph.json
cargo run -- query 'PATHS FROM user("alice") TO action("*")' --graph aws-graph.json
```

The importer builds users, groups, roles and resource nodes, `member_of` edges,
`can_assume` edges from role trust policies, and `has_permission` edges carrying the
action, resource ARN, and any `Condition` block. `Deny` and `NotAction`/`NotResource`
are not evaluated yet, so results are potential paths.

## OQL

- `PATHS FROM <node> TO <node>` every attack path between two nodes.
- `PATHS FROM <node> TO action("<pattern>")` paths to any capability matching the
  action (glob: `*`, `s3:*`, exact). Answers "who can reach full control".
- `ESCALATE FROM <node>` identities (user, group, role) reachable from a principal.
- `BLAST <node>` everything a node can reach.

Clauses on `PATHS`:

- `VIA <kind>[, <kind>...]` restrict traversal to those edge kinds.
- `WITHIN n HOPS` cap path length.

```
PATHS FROM user("alice") TO action("*") VIA can_assume, has_permission WITHIN 4 HOPS
```

A node is `kind("id")`, e.g. `user("alice")`, `role("deployer")`. `action("P")`
paths always end on an edge that actually grants `P` (glob: `*`, `s3:*`, exact).

## Stack

Rust. A hand-written OQL lexer and recursive-descent parser (no combinator
dependency, this is our language). `petgraph` for the graph, a custom
depth-capped DFS that carries the exact edge per hop, `serde` over a portable
JSON graph format, `clap` for the CLI. Path search is bounded (default 8 hops,
1000 results) with a truncation flag, so a dense graph cannot blow up.

## Status

Working: graph model, JSON loader, edge-aware bounded attack-path engine, the OQL
parser (`PATHS`, `ESCALATE`, `BLAST`, `VIA`, `WITHIN`, `ON resource`), the AWS IAM
importer, and a CLI. Next: Deny/NotAction evaluation and escalation-technique rules,
then the HTTP API and graph visualization UI, then an MCP server.
