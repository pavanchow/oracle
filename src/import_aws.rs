//! Import an AWS account into the Oracle graph.
//!
//! Input: the JSON from `aws iam get-account-authorization-details`. Policy
//! documents are expected as decoded JSON objects (the AWS CLI default), not the
//! URL-encoded strings the raw API returns.
//!
//! What it emits:
//! - a node per user, group, role (kind `user`/`group`/`role`) and per distinct
//!   resource ARN referenced (kind `resource`)
//! - `member_of` edges (user -> group)
//! - `can_assume` edges from each role's trust policy (principal -> role)
//! - `has_permission` edges for every Allow statement, one per (action, resource),
//!   carrying the action, the resource ARN, and any `Condition` block
//!
//! Known limitations (v1, documented on purpose):
//! - `Deny` statements are not evaluated, and `NotAction`/`NotResource` statements
//!   are skipped. Results are therefore *potential* paths; an explicit deny could
//!   block one. This is a false-positive risk, tracked for the next slice.
//! - Escalation techniques (AND-logic bundles) are not auto-detected yet; the
//!   importer emits faithful permissions and trust, and technique rules come next.

use crate::{Edge, GraphDoc, Node};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

pub fn import(json: &str) -> Result<GraphDoc> {
    let details: AuthDetails =
        serde_json::from_str(json).context("parsing get-account-authorization-details JSON")?;
    Builder::new(&details).build()
}

// ---- AWS input shapes (only the fields we use) ----

#[derive(Deserialize, Default)]
struct AuthDetails {
    #[serde(rename = "UserDetailList", default)]
    users: Vec<UserDetail>,
    #[serde(rename = "GroupDetailList", default)]
    groups: Vec<GroupDetail>,
    #[serde(rename = "RoleDetailList", default)]
    roles: Vec<RoleDetail>,
    #[serde(rename = "Policies", default)]
    policies: Vec<ManagedPolicy>,
}

#[derive(Deserialize)]
struct UserDetail {
    #[serde(rename = "UserName")]
    name: String,
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "GroupList", default)]
    groups: Vec<String>,
    #[serde(rename = "AttachedManagedPolicies", default)]
    attached: Vec<AttachedPolicy>,
    #[serde(rename = "UserPolicyList", default)]
    inline: Vec<InlinePolicy>,
}

#[derive(Deserialize)]
struct GroupDetail {
    #[serde(rename = "GroupName")]
    name: String,
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "AttachedManagedPolicies", default)]
    attached: Vec<AttachedPolicy>,
    #[serde(rename = "GroupPolicyList", default)]
    inline: Vec<InlinePolicy>,
}

#[derive(Deserialize)]
struct RoleDetail {
    #[serde(rename = "RoleName")]
    name: String,
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "AssumeRolePolicyDocument", default)]
    trust: Option<PolicyDocument>,
    #[serde(rename = "AttachedManagedPolicies", default)]
    attached: Vec<AttachedPolicy>,
    #[serde(rename = "RolePolicyList", default)]
    inline: Vec<InlinePolicy>,
}

#[derive(Deserialize)]
struct AttachedPolicy {
    #[serde(rename = "PolicyArn")]
    arn: String,
}

#[derive(Deserialize)]
struct InlinePolicy {
    #[serde(rename = "PolicyDocument")]
    document: PolicyDocument,
}

#[derive(Deserialize)]
struct ManagedPolicy {
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "DefaultVersionId", default)]
    default_version: String,
    #[serde(rename = "PolicyVersionList", default)]
    versions: Vec<PolicyVersion>,
}

#[derive(Deserialize)]
struct PolicyVersion {
    #[serde(rename = "Document")]
    document: PolicyDocument,
    #[serde(rename = "VersionId", default)]
    version_id: String,
}

#[derive(Deserialize, Clone)]
struct PolicyDocument {
    #[serde(rename = "Statement", default, deserialize_with = "one_or_many_stmt")]
    statements: Vec<Statement>,
}

#[derive(Deserialize, Clone)]
struct Statement {
    #[serde(rename = "Effect", default)]
    effect: String,
    #[serde(rename = "Action", default, deserialize_with = "string_or_vec")]
    action: Vec<String>,
    #[serde(rename = "NotAction", default, deserialize_with = "string_or_vec")]
    not_action: Vec<String>,
    #[serde(rename = "Resource", default, deserialize_with = "string_or_vec")]
    resource: Vec<String>,
    #[serde(rename = "NotResource", default, deserialize_with = "string_or_vec")]
    not_resource: Vec<String>,
    #[serde(rename = "Condition", default)]
    condition: Option<Map<String, Value>>,
    #[serde(rename = "Principal", default)]
    principal: Option<Value>,
}

fn string_or_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SV {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<SV>::deserialize(d)? {
        Some(SV::One(s)) => vec![s],
        Some(SV::Many(v)) => v,
        None => vec![],
    })
}

fn one_or_many_stmt<'de, D>(d: D) -> Result<Vec<Statement>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SV {
        One(Statement),
        Many(Vec<Statement>),
    }
    Ok(match Option::<SV>::deserialize(d)? {
        Some(SV::One(s)) => vec![s],
        Some(SV::Many(v)) => v,
        None => vec![],
    })
}

// ---- Builder ----

struct Builder<'a> {
    details: &'a AuthDetails,
    /// Managed policy ARN -> its default-version document.
    managed: HashMap<String, PolicyDocument>,
    /// Entity ARN -> the node id we assigned it.
    arn_to_id: HashMap<String, String>,
    nodes: Vec<Node>,
    node_ids: BTreeSet<String>,
    edges: Vec<Edge>,
    resource_nodes: BTreeSet<String>,
}

impl<'a> Builder<'a> {
    fn new(details: &'a AuthDetails) -> Self {
        let mut managed = HashMap::new();
        for p in &details.policies {
            let doc = p
                .versions
                .iter()
                .find(|v| v.version_id == p.default_version)
                .or_else(|| p.versions.first())
                .map(|v| v.document.clone());
            if let Some(doc) = doc {
                managed.insert(p.arn.clone(), doc);
            }
        }
        Builder {
            details,
            managed,
            arn_to_id: HashMap::new(),
            nodes: Vec::new(),
            node_ids: BTreeSet::new(),
            edges: Vec::new(),
            resource_nodes: BTreeSet::new(),
        }
    }

    fn build(mut self) -> Result<GraphDoc> {
        // First pass: create identity nodes and record ARN -> id.
        for u in &self.details.users {
            let id = self.add_identity(&u.name, "user", &u.arn);
            self.arn_to_id.insert(u.arn.clone(), id);
        }
        for g in &self.details.groups {
            let id = self.add_identity(&g.name, "group", &g.arn);
            self.arn_to_id.insert(g.arn.clone(), id);
        }
        for r in &self.details.roles {
            let id = self.add_identity(&r.name, "role", &r.arn);
            self.arn_to_id.insert(r.arn.clone(), id);
        }

        // Second pass: membership, permissions, trust.
        for u in &self.details.users {
            let from = self.arn_to_id[&u.arn].clone();
            for group_name in &u.groups {
                if let Some(gid) = self.group_id_by_name(group_name) {
                    self.edges.push(Edge {
                        from: from.clone(),
                        to: gid,
                        kind: "member_of".into(),
                        action: None,
                        resource: None,
                        conditions: None,
                    });
                }
            }
            let docs = self.docs_for(&u.attached, &u.inline);
            self.emit_permissions(&from, &docs);
        }
        for g in &self.details.groups {
            let from = self.arn_to_id[&g.arn].clone();
            let docs = self.docs_for(&g.attached, &g.inline);
            self.emit_permissions(&from, &docs);
        }
        for r in &self.details.roles {
            let to = self.arn_to_id[&r.arn].clone();
            let docs = self.docs_for(&r.attached, &r.inline);
            self.emit_permissions(&to, &docs);
            if let Some(trust) = &r.trust {
                self.emit_trust(&to, trust);
            }
        }

        // Materialize resource nodes referenced by permission edges.
        let resources: Vec<String> = self.resource_nodes.iter().cloned().collect();
        for arn in resources {
            self.add_node(arn, "resource");
        }

        Ok(GraphDoc {
            nodes: self.nodes,
            edges: self.edges,
        })
    }

    fn add_identity(&mut self, name: &str, kind: &str, arn: &str) -> String {
        // Prefer the readable name; fall back to the ARN if the name collides.
        let id = if self.node_ids.contains(name) {
            arn.to_string()
        } else {
            name.to_string()
        };
        self.add_node(id.clone(), kind);
        id
    }

    fn add_node(&mut self, id: String, kind: &str) {
        if self.node_ids.insert(id.clone()) {
            self.nodes.push(Node {
                id,
                kind: kind.into(),
                attrs: Map::new(),
            });
        }
    }

    fn group_id_by_name(&self, name: &str) -> Option<String> {
        self.details
            .groups
            .iter()
            .find(|g| g.name == name)
            .and_then(|g| self.arn_to_id.get(&g.arn).cloned())
    }

    fn docs_for(&self, attached: &[AttachedPolicy], inline: &[InlinePolicy]) -> Vec<PolicyDocument> {
        let mut out = Vec::new();
        for a in attached {
            if let Some(doc) = self.managed.get(&a.arn) {
                out.push(doc.clone());
            }
        }
        for i in inline {
            out.push(i.document.clone());
        }
        out
    }

    fn emit_permissions(&mut self, from: &str, docs: &[PolicyDocument]) {
        for doc in docs {
            for st in &doc.statements {
                if !st.effect.eq_ignore_ascii_case("Allow") {
                    continue; // Deny not evaluated in v1.
                }
                if !st.not_action.is_empty() || !st.not_resource.is_empty() {
                    continue; // NotAction/NotResource not modeled in v1.
                }
                let resources = if st.resource.is_empty() {
                    vec!["*".to_string()]
                } else {
                    st.resource.clone()
                };
                for action in &st.action {
                    for res in &resources {
                        // If the resource ARN is an identity in this account (e.g. a
                        // role targeted by iam:PassRole), point the edge at that
                        // identity node so escalation can traverse the final hop.
                        // Otherwise it is an opaque resource node keyed by the ARN.
                        let to = match self.arn_to_id.get(res) {
                            Some(id) => id.clone(),
                            None => {
                                self.resource_nodes.insert(res.clone());
                                res.clone()
                            }
                        };
                        self.edges.push(Edge {
                            from: from.to_string(),
                            to,
                            kind: "has_permission".into(),
                            action: Some(action.clone()),
                            resource: Some(res.clone()),
                            conditions: st.condition.clone(),
                        });
                    }
                }
            }
        }
    }

    fn emit_trust(&mut self, role_id: &str, trust: &PolicyDocument) {
        for st in &trust.statements {
            if !st.effect.eq_ignore_ascii_case("Allow") {
                continue;
            }
            if !st.action.iter().any(|a| a.eq_ignore_ascii_case("sts:AssumeRole")) {
                continue;
            }
            for arn in principal_arns(&st.principal) {
                // Resolve to an in-account node, else create an external principal.
                let from = self.arn_to_id.get(&arn).cloned().unwrap_or_else(|| {
                    self.add_node(arn.clone(), "external");
                    arn.clone()
                });
                self.edges.push(Edge {
                    from,
                    to: role_id.to_string(),
                    kind: "can_assume".into(),
                    action: Some("sts:AssumeRole".into()),
                    resource: None,
                    conditions: st.condition.clone(),
                });
            }
        }
    }
}

/// Pull the `AWS` principal ARNs out of a trust statement's `Principal` block.
fn principal_arns(principal: &Option<Value>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(Value::Object(map)) = principal {
        if let Some(aws) = map.get("AWS") {
            match aws {
                Value::String(s) => out.push(s.clone()),
                Value::Array(a) => {
                    for v in a {
                        if let Value::String(s) = v {
                            out.push(s.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Graph;

    const SAMPLE: &str = include_str!("../data/aws-authdetails-sample.json");

    #[test]
    fn imports_and_is_queryable() {
        let doc = import(SAMPLE).unwrap();
        // Round-trips through the loader.
        let json = doc.to_json_pretty().unwrap();
        let g = Graph::from_json(&json).unwrap();

        // Two real routes to s3: via the group's permissions (member_of), and via
        // assuming the deployer role (can_assume, from its trust policy).
        let r = g.paths_to_action("alice", "s3:*").unwrap();
        assert!(!r.paths.is_empty());
        let rendered: Vec<String> = r.paths.iter().map(|p| g.render_path(p)).collect();
        assert!(rendered.iter().all(|s| s.starts_with("user:alice")));
        assert!(rendered.iter().any(|s| s.contains("member_of")));
        assert!(rendered.iter().any(|s| s.contains("can_assume")));
        assert!(rendered.iter().any(|s| s.contains("s3:")));
    }

    #[test]
    fn captures_conditions_and_resources() {
        let doc = import(SAMPLE).unwrap();
        let has_conditional = doc
            .edges
            .iter()
            .any(|e| e.conditions.is_some() && e.resource.is_some());
        assert!(has_conditional);
    }

    // A real dump where eve holds iam:PassRole on a role in this account. The
    // grant must connect to the role's identity node, not a dead-end ARN resource,
    // so escalation can traverse the final hop.
    const PASSROLE: &str = r#"{
        "UserDetailList": [
            { "UserName": "eve", "UserId": "AIDAEVE", "Arn": "arn:aws:iam::123456789012:user/eve",
              "GroupList": [], "AttachedManagedPolicies": [],
              "UserPolicyList": [{ "PolicyName": "p", "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{ "Effect": "Allow", "Action": "iam:PassRole",
                                "Resource": "arn:aws:iam::123456789012:role/priv-role" }] } }] }
        ],
        "GroupDetailList": [],
        "RoleDetailList": [
            { "RoleName": "priv-role", "RoleId": "AROAPRIV",
              "Arn": "arn:aws:iam::123456789012:role/priv-role",
              "AssumeRolePolicyDocument": { "Version": "2012-10-17", "Statement": [] },
              "AttachedManagedPolicies": [], "RolePolicyList": [] }
        ],
        "Policies": []
    }"#;

    #[test]
    fn passrole_links_to_role_identity() {
        let doc = import(PASSROLE).unwrap();
        // The edge targets the role identity node id, not the raw ARN.
        assert!(doc.edges.iter().any(|e| {
            e.from == "eve" && e.to == "priv-role" && e.action.as_deref() == Some("iam:PassRole")
        }));
        // And escalation surfaces the role identity.
        let g = Graph::from_json(&doc.to_json_pretty().unwrap()).unwrap();
        let esc: Vec<String> = g
            .escalation_from("eve")
            .unwrap()
            .into_iter()
            .map(|n| g.node_label(n))
            .collect();
        assert!(esc.iter().any(|s| s == "role:priv-role"));
    }
}
