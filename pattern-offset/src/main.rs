use clap::Parser;
use kanayago::text::pattern;

/// Find offset of pattern within generated cyclic pattern
#[derive(Parser, Debug)]
#[command(name = "pattern-offset")]
#[command(about = "Find offset of pattern in cyclic pattern", long_about = None)]
struct Args {
    /// Query to locate (string or hex value)
    #[arg(short, long)]
    query: String,

    /// Length of pattern to generate (default: 8192)
    #[arg(short, long, default_value_t = 8192)]
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

    // Try to parse as hex value first (for numeric queries like 0x41334141)
    if let Some(stripped) = args.query.strip_prefix("0x").or_else(|| args.query.strip_prefix("0X")) {
        if let Ok(value) = u32::from_str_radix(stripped, 16) {
            if let Some(offset) = pattern::offset_value(args.length, value, sets_refs.as_ref().map(|v| v.as_slice())) {
                println!("[*] Exact match at offset {}", offset);
                return;
            }
        }
    }

    // Try as string pattern
    if let Some(offset) = pattern::offset(
        args.length,
        &args.query,
        sets_refs.as_ref().map(|v| v.as_slice())
    ) {
        println!("[*] Exact match at offset {}", offset);
    } else {
        eprintln!("[!] No exact matches found");
        std::process::exit(1);
    }
}
