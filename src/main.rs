use anyhow::Result;
use clap::{Parser, Subcommand};
use oracle::Graph;

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
    /// Find every attack path from one node to another.
    Paths {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "data/sample-graph.json")]
        graph: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Paths { from, to, graph } => {
            let g = Graph::load(&graph)?;
            let paths = g.paths(&from, &to)?;
            if paths.is_empty() {
                println!("no attack path from {from} to {to}");
                return Ok(());
            }
            println!("{} attack path(s) from {from} to {to}:\n", paths.len());
            for (i, p) in paths.iter().enumerate() {
                println!("[{}] {}", i + 1, g.render_path(p));
            }
        }
    }
    Ok(())
}
