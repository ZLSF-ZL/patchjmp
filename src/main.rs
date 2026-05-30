mod decode;
mod elf;
mod patch;

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use asm_rs::Arch;
use clap::Parser;
use iced_x86::{Decoder, DecoderOptions, Encoder, FlowControl, Instruction};

use crate::elf::ElfFile;
use crate::patch::{apply_patch, PatchConfig};

#[derive(Parser, Debug)]
#[command(name = "patchjmp", about = "ELF x64 binary patcher — inject code via BSS code cave")]
struct Cli {
    /// Input ELF file path
    input: PathBuf,

    /// Virtual address (hex) where the JMP will be placed
    #[arg(short, long)]
    at: String,

    /// Patch code: x64 assembly (e.g. "xor rax,rax; mov eax,60; syscall")
    /// or hex bytes (e.g. "4831c0b83c0000000f05")
    #[arg(short, long)]
    patch: String,

    /// Output file path (default: <input>.patched)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// BSS offset (hex) — skip this many bytes at the start of BSS before placing the cave.
    /// Use to avoid overwriting important BSS data (e.g. stack canary, TLS variables).
    #[arg(long)]
    bss_offset: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn parse_hex(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).with_context(|| format!("invalid hex address: {}", s))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        bail!("hex string must have even number of characters, got {}", s.len());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .context("invalid hex string")
}

/// Relocate assembled code from `orig_base` to `new_base`.
/// Fixes RIP-relative memory operands and relative branches/calls.
fn relocate_code(code: &[u8], orig_base: u64, new_base: u64) -> Result<Vec<u8>> {
    let delta = new_base as i64 - orig_base as i64;
    if delta == 0 {
        return Ok(code.to_vec());
    }

    let mut decoder = Decoder::with_ip(64, code, orig_base, DecoderOptions::NONE);
    let mut new_code = Vec::new();

    while decoder.can_decode() {
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);

        let new_ip = new_base + new_code.len() as u64;
        let mut fixed = instr;

        // Fix RIP-relative memory operands
        if fixed.is_ip_rel_memory_operand() {
            let corr = fixed.ip() as i64 - new_ip as i64;
            let d = fixed.memory_displacement64() as i64 + corr;
            fixed.set_memory_displacement64(d as u64);
        }

        // Fix relative branches and calls
        match fixed.flow_control() {
            FlowControl::ConditionalBranch => { // Conditional jump branch out of range, need to convert to opposite + near or absolute jump
                let target = fixed.near_branch_target();
                let new_offset = target as i64 - (new_ip as i64 + fixed.len() as i64);
                let abs_target = (new_ip as i64 + fixed.len() as i64 + new_offset) as u64;
                if i8::try_from(new_offset).is_ok() {
                    let code_byte = 0x70u16 + (fixed.code() as u16 & 0x0F);
                    fixed = Instruction::with_branch(unsafe { std::mem::transmute(code_byte) }, abs_target)?;
                } else if let Ok(_) = i32::try_from(new_offset) {
                    let code_byte = 0x0F80u16 + (fixed.code() as u16 & 0x0F);
                    fixed = Instruction::with_branch(unsafe { std::mem::transmute(code_byte) }, abs_target)?;
                } else {
                    bail!("conditional branch cannot reach target after relocation");
                }
            }
            FlowControl::UnconditionalBranch => { // Unconditional jump branch out of range, need to convert to absolute jump
                let target = fixed.near_branch_target();
                let new_offset = target as i64 - (new_ip as i64 + fixed.len() as i64);
                let abs_target = (new_ip as i64 + fixed.len() as i64 + new_offset) as u64;
                if fixed.code() == iced_x86::Code::Jmp_rel8_64 {
                    if i8::try_from(new_offset).is_ok() {
                        fixed = Instruction::with_branch(iced_x86::Code::Jmp_rel8_64, abs_target)?;
                    } else {
                        fixed = Instruction::with_branch(iced_x86::Code::Jmp_rel32_64, abs_target)?;
                    }
                } else if fixed.code() == iced_x86::Code::Jmp_rel32_64 {
                    fixed = Instruction::with_branch(iced_x86::Code::Jmp_rel32_64, abs_target)?;
                }
            }
            FlowControl::Call => { // Call branch out of range, need to convert to absolute indirect call via RIP-relative memory operand
                if fixed.code() == iced_x86::Code::Call_rel32_64 {
                    let target = fixed.near_branch_target();
                    fixed = Instruction::with_branch(iced_x86::Code::Call_rel32_64, target)?;
                }
            }
            _ => {}
        }

        let mut encoder = Encoder::new(64);
        if let Err(e) = encoder.encode(&fixed, new_ip) {
            bail!("failed to re-encode instruction at 0x{:x}: {}", fixed.ip(), e);
        }
        new_code.extend_from_slice(&encoder.take_buffer());
    }

    Ok(new_code)
}

/// Parse --patch input: auto-detect hex vs assembly.
/// Tries hex first (if input looks like hex), then falls back to x64 assembly.
/// PLT symbols are resolved automatically (e.g. `call _system` → call PLT[system]).
fn parse_payload(s: &str, base_addr: u64, plt_symbols: &HashMap<String, u64>) -> Result<Vec<u8>> {
    let trimmed = s.trim();
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let is_hex = !stripped.is_empty()
        && stripped.chars().all(|c| c.is_ascii_hexdigit())
        && stripped.len() % 2 == 0;

    if is_hex {
        if let Ok(bytes) = parse_hex_bytes(trimmed) {
            return Ok(bytes);
        }
    }

    // Build external labels from PLT symbols
    // Register both `system` and `_system` to handle leading underscore convention
    let mut label_buf: Vec<(String, u64)> = Vec::new();
    for (name, &addr) in plt_symbols {
        label_buf.push((name.clone(), addr));
        if !name.starts_with('_') {
            label_buf.push((format!("_{}", name), addr));
        }
    }
    let labels: Vec<(&str, u64)> = label_buf
        .iter()
        .map(|(name, addr)| (name.as_str(), *addr))
        .collect();

    // Assemble with external label resolution
    let mut asm = asm_rs::Assembler::new(Arch::X86_64);
    asm.base_address(base_addr);
    for &(name, addr) in &labels {
        asm.define_external(name, addr);
    }
    asm.emit(trimmed)
        .map_err(|e| anyhow::anyhow!("assembly error: {}", e))
        .context(format!("assembling: {}", trimmed))?;
    let result = asm.finish()
        .map_err(|e| anyhow::anyhow!("assembly error: {}", e))
        .context(format!("assembling: {}", trimmed))?;
    Ok(result.into_bytes())
}

fn main() -> Result<()> {
    use goblin::elf::program_header::PF_W;

    let cli = Cli::parse();

    let patch_addr = parse_hex(&cli.at).context("parsing --at address")?;
    let bss_offset = cli.bss_offset.as_ref().map(|s| parse_hex(s)).transpose()?.unwrap_or(0);

    // Load and parse ELF
    let mut elf = ElfFile::load(&cli.input)
        .with_context(|| format!("loading ELF: {}", cli.input.display()))?;

    let plt_symbols = elf.resolve_plt_symbols()?;

    if cli.verbose && !plt_symbols.is_empty() {
        println!("[*] PLT symbols resolved:");
        for (name, addr) in &plt_symbols {
            println!("    {} -> 0x{:x}", name, addr);
        }
    }

    // Step 1: Assemble at base 0 to determine payload size
    let raw_payload = parse_payload(&cli.patch, 0, &plt_symbols)?;

    // Step 2: Find cave segment and pre-calculate cave VA
    let (cave_vaddr, cave_filesz, cave_seg_memsz) = {
        let cave_seg = elf.segments.iter().rev()
            .find(|s| s.p_flags & PF_W != 0)
            .context("no writable PT_LOAD segment for code cave")?;
        (cave_seg.p_vaddr, cave_seg.p_filesz, cave_seg.p_memsz)
    };

    // Auto-calculate bss_offset if not specified: skip the entire BSS region
    let bss_offset = if bss_offset == 0 {
        let auto = cave_seg_memsz - cave_filesz;
        if cli.verbose {
            println!("[*] Auto bss_offset: 0x{:x} (BSS size)", auto);
        }
        auto
    } else {
        bss_offset
    };

    let cave_va = cave_vaddr + cave_filesz + bss_offset;
    if cli.verbose {
        println!("[*] Pre-calculated cave VA: 0x{:x}", cave_va);
    }

    // Step 3: Relocate payload from base 0 to cave VA
    let payload = relocate_code(&raw_payload, 0, cave_va)
        .context("relocating assembled code to cave address")?;

    let output_path = cli.output.unwrap_or_else(|| {
        let mut p = cli.input.clone();
        let ext = p.extension().map(|e| format!("{}.patched", e.to_string_lossy())).unwrap_or_else(|| "patched".into());
        p.set_extension(ext);
        p
    });

    if cli.verbose {
        println!("[*] Input:      {}", cli.input.display());
        println!("[*] Output:     {}", output_path.display());
        println!("[*] Patch at:   0x{:x}", patch_addr);
        println!("[*] Payload:    {} bytes ({})", payload.len(),
            payload.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        if bss_offset > 0 {
            println!("[*] BSS offset: 0x{:x}", bss_offset);
        }
        println!();
    }

    if cli.verbose {
        println!("[+] ELF loaded: entry=0x{:x}, {} PT_LOAD segments",
            elf.entry_point, elf.segments.len());
    }

    // Apply patch
    let config = PatchConfig {
        patch_addr,
        payload,
        bss_offset,
        verbose: cli.verbose,
    };

    let result = apply_patch(&mut elf, &config)?;

    // Save patched binary
    elf.save(&output_path)?;

    // Print summary
    println!();
    println!("=== Patch Summary ===");
    println!("  JMP site:       0x{:x}", result.jmp_addr);
    println!("  JMP bytes:      {:02x?}", result.jmp_bytes);
    println!("  Overwritten:    {} bytes (original: {:02x?})",
        result.overwritten_len, result.original_bytes);
    println!("  Code cave:      0x{:x} (file offset 0x{:x})",
        result.cave_va, result.cave_offset);
    println!("  Cave size:      {} bytes", result.cave_size);
    println!("  Output:         {}", output_path.display());

    Ok(())
}
