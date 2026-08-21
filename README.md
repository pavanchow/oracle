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

```
cargo run -- paths --from alice --to all-resources
```

```
1 attack path(s) from alice to all-resources:

[1] user:alice --[member_of]--> group:developers --[can_assume sts:AssumeRole]-->
    role:build-runner --[can_assume sts:AssumeRole]--> role:deployer
    --[has_permission iam:PutRolePolicy]--> role:admin --[has_permission *]-->
    resource:all-resources
```

## Stack

Rust. `petgraph` for the graph engine, `serde` over a portable JSON graph
format, `clap` for the CLI. Parser (`chumsky`), storage, HTTP API, graph
visualization, and an MCP server come next per the roadmap in DESIGN.md.

## Status

Foundation working: graph model, JSON loader, attack-path enumeration, and a CLI.
Query language parser is the next slice.
