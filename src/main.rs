mod decode;
mod elf;
mod patch;
mod payload;
mod report;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;

use crate::elf::ElfFile;
use crate::patch::PatchPlan;
use crate::payload::parse_payload;

#[derive(Parser, Debug)]
#[command(
    name = "patchjmp",
    about = "ELF64 x86-64 binary patcher - inject code into a new R-X PT_LOAD segment"
)]
struct Cli {
    /// Input ELF file path
    input: PathBuf,

    /// Virtual address (hex) where a JMP will be placed. Repeat for multiple
    /// patches; the Nth `--at` pairs with the Nth `--patch`.
    #[arg(short, long, required = true)]
    at: Vec<String>,

    /// Patch code: x64 assembly (e.g. "xor rax,rax; mov eax,60; syscall")
    /// or hex bytes (e.g. "4831c0b83c0000000f05"). Repeat to match `--at`.
    #[arg(short, long, required = true)]
    patch: Vec<String>,

    /// Output file path (default: <input>.patched)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Validate and report what would change without writing any output file
    #[arg(long)]
    dry_run: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn parse_hex(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).with_context(|| format!("invalid hex address: {}", s))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.at.len() != cli.patch.len() {
        bail!(
            "--at and --patch must be given the same number of times (got {} and {})",
            cli.at.len(),
            cli.patch.len()
        );
    }
    let patch_addrs = cli
        .at
        .iter()
        .map(|s| parse_hex(s))
        .collect::<Result<Vec<u64>>>()
        .context("parsing --at addresses")?;

    let mut elf = ElfFile::load(&cli.input)
        .with_context(|| format!("loading ELF: {}", cli.input.display()))?;

    let plt_symbols = elf.resolve_plt_symbols()?;
    let plan = PatchPlan::prepare(&elf, &patch_addrs, &cli.patch, |source, va| {
        parse_payload(source, va, &plt_symbols)
    })?;
    let output_path = cli.output.unwrap_or_else(|| {
        let mut path = cli.input.clone();
        path.as_mut_os_string().push(".patched");
        path
    });

    if cli.verbose {
        report::print_plan(&cli.input, &output_path, &elf, &plan, &plt_symbols);
    }
    if cli.dry_run {
        report::print_dry_run(&plan, &output_path);
        return Ok(());
    }

    let segment = plan.apply(&mut elf)?;
    elf.save(&output_path)?;
    report::print_result(&plan, &segment, &output_path, cli.verbose);
    Ok(())
}
