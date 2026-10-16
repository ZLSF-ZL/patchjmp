mod decode;
mod elf;
mod patch;
mod payload;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;

use crate::elf::{ElfFile, PatchSegmentPlan};
use crate::patch::{PatchOutcome, PatchResult, apply_patches, assemble_in_cave, decode_sites};
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

    // Step 1: lay out the new segment. Cave VA is deterministic for a given
    // input file, so payloads can be assembled straight to their final slots.
    let plan = elf.plan_patch_segment().context("planning patch segment")?;

    // Step 2: decode every patch site (validates ranges, overlap and PF_X).
    let sites = decode_sites(&elf, &patch_addrs).context("decoding patch sites")?;

    // Step 3: assemble every payload at the virtual address it will live at.
    let payloads = assemble_in_cave(plan.cave_va, &cli.patch, |_, source, va| {
        parse_payload(source, va, &plt_symbols)
    })
    .context("assembling patch payloads")?;

    let output_path = cli.output.clone().unwrap_or_else(|| {
        let mut p = cli.input.clone();
        let ext = p
            .extension()
            .map(|e| format!("{}.patched", e.to_string_lossy()))
            .unwrap_or_else(|| "patched".into());
        p.set_extension(ext);
        p
    });

    if cli.verbose {
        print_pre_patch(
            &cli,
            &output_path,
            &elf,
            &plan,
            &sites,
            &payloads,
            &plt_symbols,
        );
    }

    if cli.dry_run {
        print_dry_run(&sites, &payloads, plan.cave_va, &output_path);
        return Ok(());
    }

    let result = apply_patches(&mut elf, &plan, &sites, &payloads)?;
    elf.save(&output_path)?;

    if cli.verbose {
        print_patch_detail(&result);
    }
    print_summary(&result, &output_path);

    Ok(())
}

fn print_pre_patch(
    cli: &Cli,
    output_path: &Path,
    elf: &ElfFile,
    plan: &PatchSegmentPlan,
    sites: &[crate::patch::PatchSite],
    payloads: &[Vec<u8>],
    plt_symbols: &HashMap<String, u64>,
) {
    if !plt_symbols.is_empty() {
        println!("[*] PLT symbols resolved:");
        for (name, addr) in plt_symbols {
            println!("    {} -> 0x{:x}", name, addr);
        }
    }
    println!("[*] Input:       {}", cli.input.display());
    println!("[*] Output:      {}", output_path.display());
    println!("[*] Patches:     {}", sites.len());
    println!(
        "[*] Patch seg:   VA 0x{:x}, file 0x{:x}, header table 0x{:x} bytes",
        plan.vaddr, plan.file_offset, plan.pht_size
    );
    println!("[*] Cave VA:     0x{:x}", plan.cave_va);
    println!();
    println!(
        "[+] ELF loaded: entry=0x{:x}, {} PT_LOAD segments",
        elf.entry_point,
        elf.segments.len()
    );
    println!();

    for (i, (site, payload)) in sites.iter().zip(payloads.iter()).enumerate() {
        println!(
            "[*] Patch #{}:   at 0x{:x}, overwrites {} byte(s) across {} instruction(s)",
            i + 1,
            site.addr,
            site.overwrite_len,
            site.instructions.len()
        );
        let mut cursor = 0usize;
        for (j, &(ip, len)) in site.instructions.iter().enumerate() {
            let next = cursor + len;
            println!(
                "      [{:2}] 0x{:x}: {:02x?}",
                j,
                ip,
                &site.original_bytes[cursor..next]
            );
            cursor = next;
        }
        println!(
            "      payload: {} bytes ({})",
            payload.len(),
            payload
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
    }
    println!();
}

fn print_dry_run(
    sites: &[crate::patch::PatchSite],
    payloads: &[Vec<u8>],
    cave_va: u64,
    output_path: &Path,
) {
    println!();
    println!("=== Dry Run (nothing written) ===");
    let mut cursor = cave_va;
    for (i, (site, payload)) in sites.iter().zip(payloads.iter()).enumerate() {
        let slot = crate::patch::slot_size(payload.len())
            .map(|s| s as usize)
            .unwrap_or(payload.len() + 5);
        println!(
            "  Patch #{}:  0x{:x} -> cave 0x{:x} (payload {} bytes, slot {} bytes)",
            i + 1,
            site.addr,
            cursor,
            payload.len(),
            slot
        );
        cursor += slot as u64;
    }
    println!("  Output would be: {}", output_path.display());
    println!("  No file written (--dry-run).");
}

fn print_patch_detail(result: &PatchResult) {
    for (i, p) in result.patches.iter().enumerate() {
        println!(
            "[*] Patch #{}: JMP at 0x{:x}: {:02x?}",
            i + 1,
            p.jmp_addr,
            p.jmp_bytes
        );
    }
    println!(
        "[*] New PT_LOAD:  file 0x{:x}, VA 0x{:x}, size 0x{:x}, flags R-X",
        result.segment_offset, result.segment_vaddr, result.segment_size
    );
}

fn print_summary(result: &PatchResult, output_path: &Path) {
    println!();
    println!("=== Patch Summary ===");
    for (i, p) in result.patches.iter().enumerate() {
        print_outcome(i + 1, p);
    }
    println!(
        "  New PT_LOAD:    0x{:x} (file offset 0x{:x}, {} bytes, R-X)",
        result.segment_vaddr, result.segment_offset, result.segment_size
    );
    println!("  Output:         {}", output_path.display());
}

fn print_outcome(index: usize, p: &PatchOutcome) {
    println!("  Patch #{}:", index);
    println!("    JMP site:       0x{:x}", p.jmp_addr);
    println!("    JMP bytes:      {:02x?}", p.jmp_bytes);
    println!(
        "    Overwritten:    {} byte(s) across {} instruction(s) (original: {:02x?})",
        p.overwritten_len,
        p.overwritten_instructions.len(),
        p.original_bytes
    );
    println!(
        "    Payload:        0x{:x} (file offset 0x{:x})",
        p.cave_va, p.cave_offset
    );
    println!("    Slot size:      {} bytes", p.cave_size);
}
