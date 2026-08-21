# Oracle

**A query language whose results are attack paths across identity and network graphs.**
Not rows. You ask how a principal can reach a capability, and Oracle returns the concrete
chain of permissions and trust that gets them there, aimed at surfacing AWS IAM privilege
escalation and lateral movement. By Pavan Nallamothu.

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

## Techniques

Reachability is noise. Oracle names the exploit primitive an attack path confers,
by inspecting the permissions each principal the path yields actually holds:

```
cargo run -- query 'PATHS FROM user("alice") TO action("*")' \
  --graph aws-graph.json --techniques
```

```
[3] user:alice --[can_assume ...]--> role:deployer --[has_permission s3:PutObject ...]-->
      ! [medium] Object write (possible code execution) via role:deployer: ...
```

Detected today: full admin (`*`), Lambda code injection (`lambda:UpdateFunctionCode`
+ `iam:PassRole`, RCE), `iam:PassRole` privilege escalation, account takeover
(`iam:UpdateLoginProfile` / `iam:CreateAccessKey`), policy injection
(`iam:CreatePolicyVersion` / `Put*Policy`), and object write. The HTTP API returns a
`techniques` array on every path.

## HTTP API

Serve the engine over HTTP so a UI or an agent can query it:

```
cargo run -- serve --graph aws-graph.json --port 8080
curl -s localhost:8080/query -H 'content-type: application/json' \
  -d '{"oql":"PATHS FROM user(\"alice\") TO action(\"*\")"}'
```

- `GET /` a query-console UI: type OQL, see each attack path as a node chain with
  edge labels and severity-ranked technique badges. Served from the same binary.
- `GET /health` liveness.
- `GET /graph` the loaded graph JSON (for visualization).
- `POST /query {"oql":"..."}` structured result, or 400 with `{"error":...}`.

Path search is bounded by a visit budget (`Limits::max_visits`), so a dense graph
cannot pin the CPU per request.

## MCP server (agent-native)

Expose Oracle to an AI agent over the Model Context Protocol (stdio JSON-RPC):

```
cargo run -- mcp --graph aws-graph.json
```

Register it with an MCP client, e.g. Claude Code:

```
claude mcp add oracle -- /path/to/oracle mcp --graph /path/to/aws-graph.json
```

Tools: `oracle_query` (run any OQL), `oracle_escalate` (escalation targets for a
principal), `oracle_graph` (the loaded graph). An agent can ask "how does this
principal reach admin" and get a walkable attack path back as structured JSON.

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
importer, structured JSON query results, exploit-technique detection, and an HTTP
API with a query-console UI, and an MCP server for agents. `ESCALATE` requires a real
privilege-boundary crossing, path search is compute-bounded, and a grant whose resource
ARN is an identity in the account resolves to that identity, so PassRole escalation
traverses on real imported data. Next: Deny/NotAction evaluation, and mapping Service and
Federated trust principals so a compromised Lambda assuming its role shows as a path.
