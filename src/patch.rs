use anyhow::{Context, Result};
use goblin::elf::program_header::{PF_W, PF_X};

use crate::decode::decode_patch_site;
use crate::elf::ElfFile;

/// Minimum number of bytes to overwrite for a near JMP (5 bytes: E9 + rel32).
const NEAR_JMP_SIZE: usize = 5;
/// Size of an indirect JMP (14 bytes: FF 25 00 00 00 00 + 8-byte addr).
const INDIRECT_JMP_SIZE: usize = 14;

pub struct PatchConfig {
    /// Virtual address where the JMP will be placed.
    pub patch_addr: u64,
    /// The patch code payload (raw bytes).
    pub payload: Vec<u8>,
    /// BSS offset — skip this many bytes at the start of BSS before placing the cave.
    pub bss_offset: u64,
    /// Whether to print verbose output.
    pub verbose: bool,
}

pub struct PatchResult {
    /// Virtual address where the JMP was placed.
    pub jmp_addr: u64,
    /// The JMP instruction bytes written.
    pub jmp_bytes: Vec<u8>,
    /// Virtual address of the code cave.
    pub cave_va: u64,
    /// File offset of the code cave.
    pub cave_offset: u64,
    /// Total size of the code cave.
    pub cave_size: u64,
    /// The original bytes that were overwritten.
    pub original_bytes: Vec<u8>,
    /// Number of bytes overwritten at the JMP site.
    pub overwritten_len: usize,
}

/// Encode an indirect JMP: FF 25 00 00 00 00 [8-byte absolute addr]
fn encode_jmp_abs(_from: u64, to: u64) -> [u8; INDIRECT_JMP_SIZE] {
    let mut buf = [0u8; INDIRECT_JMP_SIZE];
    buf[0] = 0xFF;
    buf[1] = 0x25;
    buf[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    buf[6..14].copy_from_slice(&to.to_le_bytes());
    buf
}

/// Try to encode a JMP from `from` to `to`.
/// Uses rel32 (5 bytes) if possible, otherwise indirect (14 bytes).
fn encode_jmp(from: u64, to: u64) -> Result<Vec<u8>> {
    let offset = to as i64 - (from as i64 + NEAR_JMP_SIZE as i64);
    if let Ok(offset_i32) = i32::try_from(offset) {
        let mut buf = [0u8; NEAR_JMP_SIZE];
        buf[0] = 0xE9;
        buf[1..5].copy_from_slice(&offset_i32.to_le_bytes());
        Ok(buf.to_vec())
    } else {
        Ok(encode_jmp_abs(from, to).to_vec())
    }
}

/// Apply the patch to the ELF binary.
///
/// Cave layout: `payload + JMP back`
/// The user is responsible for handling the original displaced instructions
/// manually within their payload code.
pub fn apply_patch(elf: &mut ElfFile, config: &PatchConfig) -> Result<PatchResult> {
    let PatchConfig {
        patch_addr,
        payload,
        bss_offset,
        verbose,
    } = config;

    // 1. Find the segment containing the patch address
    let target_seg = elf
        .find_segment_by_va(*patch_addr)
        .with_context(|| format!("no segment contains patch address 0x{:x}", patch_addr))?;

    if *verbose {
        println!(
            "[*] Target segment: VA 0x{:x} - 0x{:x} (flags: 0x{:x})",
            target_seg.p_vaddr,
            target_seg.p_vaddr + target_seg.p_memsz,
            target_seg.p_flags
        );
    }

    // 2. Find the BSS / last RW segment for the code cave
    let cave_seg = elf
        .segments
        .iter()
        .rev()
        .find(|s| s.p_flags & PF_W != 0)
        .context("no writable PT_LOAD segment found for code cave")?
        .clone();

    if *verbose {
        println!(
            "[*] Cave segment: VA 0x{:x} - 0x{:x} (flags: 0x{:x})",
            cave_seg.p_vaddr,
            cave_seg.p_vaddr + cave_seg.p_memsz,
            cave_seg.p_flags
        );
    }

    // 3. Determine JMP encoding (try near first, fall back to indirect)
    let test_jmp = encode_jmp(*patch_addr, *patch_addr)?;
    let jmp_size = test_jmp.len();

    // 4. Decode instructions at the patch site — find complete instruction boundaries
    let patch_file_offset = elf.va_to_offset(*patch_addr)? as usize;
    let code_region = &elf.data[patch_file_offset..];
    let decoded = decode_patch_site(code_region, *patch_addr, jmp_size)
        .context("decoding instructions at patch site")?;

    let overwrite_len = decoded.total_len;
    let original_bytes = decoded.bytes.clone();

    if *verbose {
        println!(
            "[*] Overwriting {} bytes ({} complete instruction(s)) at 0x{:x}:",
            overwrite_len,
            decoded.instructions.len(),
            patch_addr
        );
        for (i, instr) in decoded.instructions.iter().enumerate() {
            println!(
                "    [{:2}] 0x{:x}: {:02x?}",
                i,
                instr.ip(),
                &original_bytes[decoded.instructions[..i].iter().map(|i| i.len()).sum::<usize>()
                    ..decoded.instructions[..=i].iter().map(|i| i.len()).sum::<usize>()]
            );
        }
    }

    // 5. Calculate cave size: payload + JMP back, 8-byte aligned, minimum 8
    let cave_total_size = crate::elf::align_up(payload.len() as u64 + NEAR_JMP_SIZE as u64, 8).max(8);

    // 6. Extend the cave segment (cave placed at BSS file offset + bss_offset)
    let cave_file_offset = elf.extend_segment_for_cave(&cave_seg, cave_total_size, *bss_offset)?;

    let cave_va_calc = cave_seg.p_vaddr + (cave_file_offset - cave_seg.p_offset);

    // 7. Ensure file is large enough before writing
    elf.ensure_file_size();

    // 8. Write JMP at patch location
    let jmp_to_cave = encode_jmp(*patch_addr, cave_va_calc)?;

    for (i, &byte) in jmp_to_cave.iter().enumerate() {
        elf.data[patch_file_offset + i] = byte;
    }

    if *verbose {
        println!("[*] JMP written at 0x{:x}: {:02x?}", patch_addr, jmp_to_cave);
    }

    // 9. Build cave content: payload + JMP back + NOP padding
    let original_code_addr = *patch_addr + overwrite_len as u64;
    let jmp_back_addr = cave_va_calc + payload.len() as u64;
    let jmp_back = encode_jmp(jmp_back_addr, original_code_addr)?;

    let mut cave_data = Vec::new();
    cave_data.extend_from_slice(payload);
    cave_data.extend_from_slice(&jmp_back);
    // NOP-pad to cave_total_size
    while (cave_data.len() as u64) < cave_total_size {
        cave_data.push(0x90);
    }

    // Write cave data to the file
    let cave_file_start = cave_file_offset as usize;
    elf.data[cave_file_start..cave_file_start + cave_data.len()].copy_from_slice(&cave_data);

    if *verbose {
        println!(
            "[*] Code cave at VA 0x{:x} (file offset 0x{:x}):",
            cave_va_calc, cave_file_offset
        );
        println!("    Payload:            {} bytes", payload.len());
        println!("    JMP back:           {} bytes", jmp_back.len());
        println!("    Total:              {} bytes", cave_data.len());
    }

    // 10. Modify segment flags: add PF_X
    let new_flags = cave_seg.p_flags | PF_X;
    elf.update_segment(&cave_seg, Some(new_flags), None, None)?;

    if *verbose {
        println!(
            "[*] Segment flags updated: 0x{:x} -> 0x{:x}",
            cave_seg.p_flags, new_flags
        );
    }

    Ok(PatchResult {
        jmp_addr: *patch_addr,
        jmp_bytes: jmp_to_cave,
        cave_va: cave_va_calc,
        cave_offset: cave_file_offset,
        cave_size: cave_total_size,
        original_bytes,
        overwritten_len: overwrite_len,
    })
}
