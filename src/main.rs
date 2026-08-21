use anyhow::Result;
use clap::{Parser, Subcommand};
use oracle::query::{parse, Query, Target};
use oracle::{Graph, PathSet};

#[derive(Parser)]
#[command(
    name = "oracle",
    version,
    about = "Attack-path query engine over identity and network graphs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Find every attack path from one node to another (raw, by id).
    Paths {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "data/sample-graph.json")]
        graph: String,
    },
    /// Run an OQL query, e.g. 'PATHS FROM user("alice") TO action("*")'.
    Query {
        #[arg(value_name = "OQL")]
        text: String,
        #[arg(long, default_value = "data/sample-graph.json")]
        graph: String,
    },
}

fn print_paths(g: &Graph, r: &PathSet) {
    if r.paths.is_empty() {
        println!("no attack path found");
        return;
    }
    let note = if r.truncated { " (truncated)" } else { "" };
    println!("{} attack path(s){}:\n", r.paths.len(), note);
    for (i, p) in r.paths.iter().enumerate() {
        println!("[{}] {}", i + 1, g.render_path(p));
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Paths { from, to, graph } => {
            let g = Graph::load(&graph)?;
            print_paths(&g, &g.paths(&from, &to)?);
        }
        Cmd::Query { text, graph } => {
            let g = Graph::load(&graph)?;
            match parse(&text)? {
                Query::Paths { from_id, to, .. } => {
                    let r = match to {
                        Target::Node { id, .. } => g.paths(&from_id, &id)?,
                        Target::Action(pat) => g.paths_to_action(&from_id, &pat)?,
                    };
                    print_paths(&g, &r);
                }
                Query::Escalate { from_id, .. } => {
                    let roles: Vec<_> = g
                        .reachable_from(&from_id)?
                        .into_iter()
                        .filter(|&n| g.node_kind_of(n) == "role")
                        .collect();
                    if roles.is_empty() {
                        println!("no roles reachable from {from_id}");
                    } else {
                        println!("{} role(s) reachable from {from_id}:", roles.len());
                        for n in roles {
                            println!("  {}", g.node_label(n));
                        }
                    }
                }
                Query::Blast { from_id, .. } => {
                    let nodes = g.reachable_from(&from_id)?;
                    if nodes.is_empty() {
                        println!("{from_id} reaches nothing");
                    } else {
                        println!("{from_id} can reach {} node(s):", nodes.len());
                        for n in nodes {
                            println!("  {}", g.node_label(n));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
