use clap::Parser;
use kanayago::text::pattern;

/// Generate cyclic pattern for exploit development
#[derive(Parser, Debug)]
#[command(name = "pattern-create")]
#[command(about = "Generate cyclic pattern for exploit development", long_about = None)]
struct Args {
    /// Length of the pattern to generate
    #[arg(short, long)]
    length: usize,

    /// Custom pattern sets (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    sets: Option<Vec<String>>,
}

fn main() {
    let args = Args::parse();

    let sets_refs: Option<Vec<&str>> = args.sets.as_ref().map(|s| {
        s.iter().map(|st| st.as_str()).collect()
    });

    let pattern = pattern::create(
        args.length,
        sets_refs.as_ref().map(|v| v.as_slice())
    );

    println!("{}", pattern);
}
