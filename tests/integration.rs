//! Public-API integration tests for oracle, driving the attack-path engine the
//! way a dependent would: build a `Graph` from JSON, then query it through
//! `paths`, `paths_to_action`, `escalation_from`, `reachable_from`, `run_oql`,
//! `render_path`, and the `action_matches` glob helper.

use oracle::{action_matches, Graph, Limits};

// A small AWS-shaped identity graph:
//   alice -can_assume-> deployer -PassRole-> admin -s3:*-> bucket
//   deployer -s3:GetObject-> bucket        (a second, shorter route)
//   bob -s3:GetObject (MFA-gated)-> bucket
const GRAPH: &str = r#"{
  "nodes": [
    {"id":"alice","kind":"user"},
    {"id":"deployer","kind":"role"},
    {"id":"admin","kind":"role"},
    {"id":"bucket","kind":"resource"},
    {"id":"bob","kind":"user"}
  ],
  "edges": [
    {"from":"alice","to":"deployer","kind":"can_assume"},
    {"from":"deployer","to":"bucket","kind":"has_permission","action":"s3:GetObject","resource":"arn:aws:s3:::bucket/*"},
    {"from":"deployer","to":"admin","kind":"has_permission","action":"iam:PassRole"},
    {"from":"admin","to":"bucket","kind":"has_permission","action":"s3:*"},
    {"from":"bob","to":"bucket","kind":"has_permission","action":"s3:GetObject","conditions":{"aws:MultiFactorAuthPresent":"true"}}
  ]
}"#;

fn graph() -> Graph {
    Graph::from_json(GRAPH).expect("sample graph should parse")
}

#[test]
fn enumerates_every_simple_path_between_two_nodes() {
    let g = graph();
    let ps = g.paths("alice", "bucket").unwrap();
    // Two distinct routes: the direct s3:GetObject grant and the PassRole
    // detour through admin.
    assert_eq!(ps.paths.len(), 2);
    assert!(!ps.truncated);
    let rendered: Vec<String> = ps.paths.iter().map(|p| g.render_path(p)).collect();
    assert!(rendered.iter().any(|r| r.contains("iam:PassRole") && r.contains("role:admin")));
    assert!(rendered.iter().any(|r| r.contains("s3:GetObject") && r.ends_with("resource:bucket")));
    // Every path starts at the queried node.
    assert!(ps.paths.iter().all(|p| g.node_id_of(p.start) == "alice"));
}

#[test]
fn no_route_yields_an_empty_path_set() {
    let g = graph();
    // A resource is a sink: nothing leaves it.
    assert!(g.paths("bucket", "alice").unwrap().paths.is_empty());
    // A principal that shares no route with the target.
    assert!(g.paths("bob", "admin").unwrap().paths.is_empty());
}

#[test]
fn depth_limit_prunes_paths_longer_than_the_cap() {
    let g = graph();
    let shallow = Limits { max_depth: 1, ..Limits::default() };
    // bucket is 2 hops from alice, so a 1-hop cap finds nothing.
    assert!(g.paths_with("alice", "bucket", shallow, &[]).unwrap().paths.is_empty());
    // The direct route is exactly 2 hops and reappears at depth 2.
    let two = Limits { max_depth: 2, ..Limits::default() };
    let ps = g.paths_with("alice", "bucket", two, &[]).unwrap();
    assert_eq!(ps.paths.len(), 1);
    assert_eq!(ps.paths[0].hops(), 2);
}

#[test]
fn via_filter_restricts_to_allowed_edge_kinds() {
    let g = graph();
    // Only can_assume edges: alice reaches deployer but cannot touch the bucket.
    let via = vec!["can_assume".to_string()];
    assert!(g.paths_with("alice", "bucket", Limits::default(), &via).unwrap().paths.is_empty());
    assert_eq!(g.paths_with("alice", "deployer", Limits::default(), &via).unwrap().paths.len(), 1);
}

#[test]
fn paths_to_action_ends_on_a_matching_grant() {
    let g = graph();
    let ps = g.paths_to_action("alice", "s3:GetObject").unwrap();
    assert_eq!(ps.paths.len(), 2);
    // Each returned path must terminate on an edge that actually grants the
    // queried action (directly or via an s3:* wildcard).
    for p in &ps.paths {
        let last = p.steps.last().unwrap();
        assert_eq!(g.node_id_of(last.to), "bucket");
    }
}

#[test]
fn escalation_reports_only_boundary_crossing_principals() {
    let g = graph();
    let labels: Vec<String> =
        g.escalation_from("alice").unwrap().into_iter().map(|n| g.node_label(n)).collect();
    assert_eq!(labels.len(), 2);
    assert!(labels.contains(&"role:deployer".to_string())); // via can_assume
    assert!(labels.contains(&"role:admin".to_string())); // via iam:PassRole
    // The bucket is a resource, never an escalation target; bob is unrelated.
    assert!(!labels.iter().any(|l| l.starts_with("resource:")));
    assert!(!labels.contains(&"user:bob".to_string()));
}

#[test]
fn reachable_from_is_the_full_forward_closure() {
    let g = graph();
    let labels: Vec<String> =
        g.reachable_from("alice").unwrap().into_iter().map(|n| g.node_label(n)).collect();
    assert_eq!(labels.len(), 3);
    for expected in ["role:deployer", "role:admin", "resource:bucket"] {
        assert!(labels.contains(&expected.to_string()), "missing {expected}");
    }
    assert!(!labels.contains(&"user:alice".to_string())); // excludes the start
}

#[test]
fn conditional_grants_are_flagged_when_rendered() {
    let g = graph();
    let ps = g.paths("bob", "bucket").unwrap();
    assert_eq!(ps.paths.len(), 1);
    let rendered = g.render_path(&ps.paths[0]);
    assert!(rendered.contains("(conditional: aws:MultiFactorAuthPresent)"), "got: {rendered}");
}

#[test]
fn run_oql_matches_the_direct_query_apis() {
    let g = graph();
    let paths = g.run_oql(r#"PATHS FROM user("alice") TO resource("bucket")"#).unwrap().to_string();
    assert!(paths.contains("\"kind\":\"paths\""));
    assert!(paths.contains("\"count\":2"), "{paths}");

    let esc = g.run_oql(r#"ESCALATE FROM user("alice")"#).unwrap().to_string();
    assert!(esc.contains("\"kind\":\"escalation\""));
    assert!(esc.contains("role:admin"));

    let blast = g.run_oql(r#"BLAST user("alice")"#).unwrap().to_string();
    assert!(blast.contains("\"kind\":\"reach\""));
    assert!(blast.contains("\"count\":3"), "{blast}");

    // WITHIN caps depth so the 2-hop bucket becomes unreachable.
    let capped = g.run_oql(r#"PATHS FROM user("alice") TO resource("bucket") WITHIN 1 HOPS"#).unwrap().to_string();
    assert!(capped.contains("\"count\":0"), "{capped}");
}

#[test]
fn invalid_inputs_error_instead_of_panicking() {
    // Unknown start node.
    assert!(graph().paths("ghost", "bucket").is_err());
    // Duplicate node id.
    let dup = r#"{"nodes":[{"id":"a","kind":"user"},{"id":"a","kind":"role"}],"edges":[]}"#;
    match Graph::from_json(dup) {
        Err(e) => assert!(e.to_string().contains("duplicate node id"), "{e}"),
        Ok(_) => panic!("duplicate node id should be rejected"),
    }
    // Edge referencing a node that does not exist.
    let bad_edge = r#"{"nodes":[{"id":"a","kind":"user"}],"edges":[{"from":"a","to":"nope","kind":"can_assume"}]}"#;
    assert!(Graph::from_json(bad_edge).is_err());
    // Malformed OQL.
    assert!(graph().run_oql("PATHS FROM user(alice)").is_err());
}

#[test]
fn action_glob_matching_follows_iam_semantics() {
    // A "*" grant covers anything.
    assert!(action_matches("s3:GetObject", "*"));
    // A service wildcard grant covers a specific action query.
    assert!(action_matches("s3:GetObject", "s3:*"));
    // Exact match.
    assert!(action_matches("s3:GetObject", "s3:GetObject"));
    // A different action does not match.
    assert!(!action_matches("s3:GetObject", "s3:PutObject"));
    // A "*" query matches any grant.
    assert!(action_matches("*", "iam:PassRole"));
}
