use std::collections::HashMap;
use std::path::Path;

use crate::elf::{ElfFile, LoadSegment};
use crate::patch::PatchPlan;

pub fn print_plan(
    input: &Path,
    output: &Path,
    elf: &ElfFile,
    plan: &PatchPlan,
    plt_symbols: &HashMap<String, u64>,
) {
    if !plt_symbols.is_empty() {
        println!("[*] PLT symbols resolved:");
        for (name, addr) in plt_symbols {
            println!("    {name} -> 0x{addr:x}");
        }
    }
    let seg = plan.segment();
    println!("[*] Input:       {}", input.display());
    println!("[*] Output:      {}", output.display());
    println!("[*] Patches:     {}", plan.patches().len());
    println!(
        "[*] Patch seg:   VA 0x{:x}, file 0x{:x}, header table 0x{:x} bytes",
        seg.vaddr, seg.file_offset, seg.pht_size
    );
    println!("[*] Cave VA:     0x{:x}\n", seg.cave_va);
    println!(
        "[+] ELF loaded: entry=0x{:x}, {} PT_LOAD segments\n",
        elf.entry_point,
        elf.segments.len()
    );

    for (i, p) in plan.patches().iter().enumerate() {
        let site = &p.site;
        let mut bytes = site.original_bytes.as_slice();
        println!(
            "[*] Patch #{}:   at 0x{:x}, overwrites {} byte(s) across {} instruction(s)",
            i + 1,
            site.addr,
            bytes.len(),
            site.instructions.len()
        );
        for (j, instr) in site.instructions.iter().enumerate() {
            let (instruction, rest) = bytes.split_at(instr.len);
            println!("      [{j:2}] 0x{:x}: {instruction:02x?}", instr.ip);
            bytes = rest;
        }
        let payload = p.payload();
        let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
        println!("      payload: {} bytes ({hex})", payload.len());
    }
    println!();
}

pub fn print_dry_run(plan: &PatchPlan, output: &Path) {
    println!("\n=== Dry Run (nothing written) ===");
    for (i, p) in plan.patches().iter().enumerate() {
        println!(
            "  Patch #{}:  0x{:x} -> cave 0x{:x} (payload {} bytes, slot {} bytes)",
            i + 1,
            p.site.addr,
            p.cave_va,
            p.payload().len(),
            p.slot_size()
        );
    }
    println!("  Output would be: {}", output.display());
    println!("  No file written (--dry-run).");
}

pub fn print_result(plan: &PatchPlan, seg: &LoadSegment, output: &Path, verbose: bool) {
    if verbose {
        for (i, p) in plan.patches().iter().enumerate() {
            println!(
                "[*] Patch #{}: JMP at 0x{:x}: {:02x?}",
                i + 1,
                p.site.addr,
                p.jmp
            );
        }
        println!(
            "[*] New PT_LOAD:  file 0x{:x}, VA 0x{:x}, size 0x{:x}, flags R-X",
            seg.p_offset, seg.p_vaddr, seg.p_filesz
        );
    }

    println!("\n=== Patch Summary ===");
    for (i, p) in plan.patches().iter().enumerate() {
        let site = &p.site;
        println!("  Patch #{}:", i + 1);
        println!("    JMP site:       0x{:x}", site.addr);
        println!("    JMP bytes:      {:02x?}", p.jmp);
        println!(
            "    Overwritten:    {} byte(s) across {} instruction(s) (original: {:02x?})",
            site.original_bytes.len(),
            site.instructions.len(),
            site.original_bytes
        );
        println!(
            "    Payload:        0x{:x} (file offset 0x{:x})",
            p.cave_va, p.cave_offset
        );
        println!("    Slot size:      {} bytes", p.slot_size());
    }
    println!(
        "  New PT_LOAD:    0x{:x} (file offset 0x{:x}, {} bytes, R-X)",
        seg.p_vaddr, seg.p_offset, seg.p_filesz
    );
    println!("  Output:         {}", output.display());
}
