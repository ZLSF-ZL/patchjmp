use anyhow::{Result, bail};

use crate::elf::{ElfFile, PatchSegmentPlan};

use super::layout::{cave_extent, slot_addresses, slot_size};
use super::site::PatchSite;
use super::{PatchOutcome, PatchResult, encode_jmp};

/// Install one shared R-X segment and wire up every patch.
///
/// `plan` must come from [`ElfFile::plan_patch_segment`] on the same `elf`, and
/// `payloads[i]` must already be assembled for the slot that corresponds to
/// `sites[i]` (see [`assemble_in_cave`]).
pub fn apply_patches(
    elf: &mut ElfFile,
    plan: &PatchSegmentPlan,
    sites: &[PatchSite],
    payloads: &[Vec<u8>],
) -> Result<PatchResult> {
    if sites.len() != payloads.len() {
        bail!(
            "internal error: {} patch sites but {} payloads",
            sites.len(),
            payloads.len()
        );
    }
    if sites.is_empty() {
        bail!("no patch sites given");
    }

    let sizes: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let slots = slot_addresses(plan.cave_va, &sizes)?;
    let total_cave = cave_extent(&sizes)?;

    let segment = elf.install_patch_segment(plan, total_cave)?;
    let cave_base = segment.p_offset + plan.cave_offset_in_segment;

    let mut patches = Vec::with_capacity(sites.len());
    for (i, (site, payload)) in sites.iter().zip(payloads.iter()).enumerate() {
        let cave_va = slots[i];
        let slot = slot_size(payload.len())?;

        // payload, back-JMP, then NOP padding up to the reserved slot.
        let back = encode_jmp(
            cave_va + payload.len() as u64,
            site.addr + site.overwrite_len as u64,
        )?;
        let mut bytes = Vec::with_capacity(slot as usize);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&back);
        bytes.resize(slot as usize, 0x90);

        let cave_offset = (cave_base + (cave_va - plan.cave_va)) as usize;
        if cave_offset + bytes.len() > elf.len() {
            bail!("internal error: patch slot exceeds the appended segment");
        }
        elf.write_bytes(cave_offset..cave_offset + bytes.len(), &bytes)?;

        // forward JMP at the patch site
        let jmp = encode_jmp(site.addr, cave_va)?;
        let site_offset = site.file_offset as usize;
        elf.write_bytes(site_offset..site_offset + jmp.len(), &jmp)?;

        patches.push(PatchOutcome {
            jmp_addr: site.addr,
            jmp_bytes: jmp,
            cave_va,
            cave_offset: cave_offset as u64,
            cave_size: slot,
            overwritten_len: site.overwrite_len,
            original_bytes: site.original_bytes.clone(),
            overwritten_instructions: site.instructions.clone(),
        });
    }

    Ok(PatchResult {
        patches,
        segment_offset: segment.p_offset,
        segment_vaddr: segment.p_vaddr,
        segment_size: segment.p_filesz,
    })
}
