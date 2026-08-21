//! Exploit-technique detection over attack paths.
//!
//! A reachability calculator tells you alice can reach a role. That is noise.
//! An operator wants the primitive: "alice has a Lambda code-injection path to
//! RCE." Techniques translate a path into named, ranked exploit primitives.
//!
//! We do NOT bake techniques into the graph as synthetic nodes. We evaluate them
//! over the principals an attack path yields, inspecting the permissions each of
//! those principals actually holds. That keeps the graph pure and works on real
//! importer output, where an AND-primitive (e.g. lambda + passrole) is two grants
//! held by one assumable role, not a single edge.

use crate::{action_matches, AttackPath, Graph};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub technique: String,
    pub severity: String,
    pub principal: String,
    pub why: String,
}

fn holds(actions: &[&str], primitive: &str) -> bool {
    actions.iter().any(|grant| action_matches(primitive, grant))
}

/// Techniques conferred by an attack path, ranked most severe first.
pub fn detect(g: &Graph, p: &AttackPath) -> Vec<Finding> {
    let mut out = Vec::new();
    for idx in g.path_principals(p) {
        let actions = g.granted_actions(idx);
        if actions.is_empty() {
            continue;
        }
        let who = format!("{}:{}", g.node_kind_of(idx), g.node_id_of(idx));
        let mut add = |technique: &str, severity: &str, why: &str| {
            out.push(Finding {
                technique: technique.into(),
                severity: severity.into(),
                principal: who.clone(),
                why: why.into(),
            })
        };

        // A literal `*` grant is admin. (Do not use action_matches here: a query
        // of "*" matches every grant, which would flag any permission as admin.)
        // Admin implies every primitive, so report it alone and skip the rest,
        // otherwise an admin principal drowns the operator in redundant findings.
        if actions.iter().any(|grant| *grant == "*") {
            add("Full administrative access", "critical", "holds action *");
            continue;
        }

        let lambda = holds(&actions, "lambda:UpdateFunctionCode");
        let passrole = holds(&actions, "iam:PassRole");
        if lambda && passrole {
            add(
                "Lambda code injection (RCE)",
                "critical",
                "holds lambda:UpdateFunctionCode and iam:PassRole",
            );
        } else if passrole {
            add(
                "iam:PassRole privilege escalation",
                "high",
                "can pass a role to a service it controls",
            );
        }

        if holds(&actions, "iam:UpdateLoginProfile") || holds(&actions, "iam:CreateAccessKey") {
            add(
                "Account takeover",
                "high",
                "can set another principal's console password or access key",
            );
        }

        if holds(&actions, "iam:CreatePolicyVersion")
            || holds(&actions, "iam:PutUserPolicy")
            || holds(&actions, "iam:PutRolePolicy")
        {
            add(
                "Policy injection",
                "high",
                "can rewrite an attached policy to grant itself more",
            );
        }

        if holds(&actions, "s3:PutObject") {
            add(
                "Object write (possible code execution)",
                "medium",
                "can write objects; RCE if a bucket has a Lambda or pipeline trigger",
            );
        }
    }

    let rank = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    };
    out.sort_by(|a, b| {
        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then(a.technique.cmp(&b.technique))
            .then(a.principal.cmp(&b.principal))
    });
    out.dedup_by(|a, b| a.technique == b.technique && a.principal == b.principal);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rce_from_lambda_plus_passrole() {
        // A role that holds both lambda:UpdateFunctionCode and iam:PassRole,
        // reachable by assuming it, is an RCE primitive.
        let j = r#"{
            "nodes":[
                {"id":"alice","kind":"user"},
                {"id":"builder","kind":"role"},
                {"id":"fn","kind":"resource"},
                {"id":"admin-role","kind":"role"}
            ],
            "edges":[
                {"from":"alice","to":"builder","kind":"can_assume","action":"sts:AssumeRole"},
                {"from":"builder","to":"fn","kind":"has_permission","action":"lambda:UpdateFunctionCode"},
                {"from":"builder","to":"admin-role","kind":"has_permission","action":"iam:PassRole"}
            ]}"#;
        let g = Graph::from_json(j).unwrap();
        // Reach the builder role (endpoint principal that holds the combo).
        let r = g.paths("alice", "builder").unwrap();
        assert_eq!(r.paths.len(), 1);
        let findings = detect(&g, &r.paths[0]);
        assert!(findings
            .iter()
            .any(|f| f.technique.contains("RCE") && f.principal == "role:builder"));
    }

    #[test]
    fn plain_reachability_has_no_technique() {
        let j = r#"{
            "nodes":[{"id":"alice","kind":"user"},{"id":"devs","kind":"group"},{"id":"b","kind":"resource"}],
            "edges":[
                {"from":"alice","to":"devs","kind":"member_of"},
                {"from":"devs","to":"b","kind":"has_permission","action":"s3:GetObject"}
            ]}"#;
        let g = Graph::from_json(j).unwrap();
        let r = g.paths("alice", "b").unwrap();
        assert!(detect(&g, &r.paths[0]).is_empty());
    }
}
