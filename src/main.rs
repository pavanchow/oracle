use anyhow::Result;
use clap::{Parser, Subcommand};
use oracle::query::{parse, Query, Target};
use oracle::{Graph, Limits, PathSet};

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
        /// Annotate each path with the exploit techniques it confers.
        #[arg(long)]
        techniques: bool,
    },
    /// Import `aws iam get-account-authorization-details` JSON into a graph.
    ImportAws {
        /// Path to the get-account-authorization-details JSON.
        #[arg(long)]
        input: String,
        /// Where to write the graph JSON (defaults to stdout).
        #[arg(long)]
        output: Option<String>,
    },
    /// Serve the HTTP API over a graph (POST /query, GET /graph, GET /health).
    Serve {
        #[arg(long, default_value = "data/sample-graph.json")]
        graph: String,
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
}

fn print_paths(g: &Graph, r: &PathSet, techniques: bool) {
    if r.paths.is_empty() {
        println!("no attack path found");
        return;
    }
    let note = if r.truncated { " (truncated)" } else { "" };
    println!("{} attack path(s){}:\n", r.paths.len(), note);
    for (i, p) in r.paths.iter().enumerate() {
        println!("[{}] {}", i + 1, g.render_path(p));
        if techniques {
            for f in oracle::technique::detect(g, p) {
                println!(
                    "      ! [{}] {} via {}: {}",
                    f.severity, f.technique, f.principal, f.why
                );
            }
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Paths { from, to, graph } => {
            let g = Graph::load(&graph)?;
            print_paths(&g, &g.paths(&from, &to)?, false);
        }
        Cmd::Query {
            text,
            graph,
            techniques,
        } => {
            let g = Graph::load(&graph)?;
            match parse(&text)? {
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
                        Target::Node { id, .. } => g.paths_with(&from_id, &id, limits, &via)?,
                        Target::Action(pat) => g.paths_to_action_with(
                            &from_id,
                            &pat,
                            limits,
                            &via,
                            on_resource.as_deref(),
                        )?,
                    };
                    print_paths(&g, &r, techniques);
                }
                Query::Escalate { from_id, .. } => {
                    // Real escalation crosses a privilege boundary (a can_assume
                    // hop), not just reaching your own group.
                    let targets = g.escalation_from(&from_id)?;
                    if targets.is_empty() {
                        println!("no privilege escalation from {from_id}");
                    } else {
                        println!(
                            "{} escalation target(s) from {from_id}:",
                            targets.len()
                        );
                        for n in targets {
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
        Cmd::ImportAws { input, output } => {
            let json = std::fs::read_to_string(&input)?;
            let doc = oracle::import_aws::import(&json)?;
            let out = doc.to_json_pretty()?;
            match output {
                Some(path) => {
                    std::fs::write(&path, out)?;
                    eprintln!(
                        "wrote {} nodes, {} edges to {path}",
                        doc.nodes.len(),
                        doc.edges.len()
                    );
                }
                None => println!("{out}"),
            }
        }
        Cmd::Serve { graph, port } => {
            oracle::server::serve(&graph, port)?;
        }
    }
    Ok(())
}
