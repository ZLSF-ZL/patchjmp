use anyhow::{Context, Result, bail};

use crate::elf::{ElfFile, LoadSegment, PatchSegmentPlan, align_up};

use super::jmp::{NEAR_JMP_SIZE, encode_jmp};
use super::site::{PatchSite, decode_sites};

pub struct PlannedPatch {
    pub site: PatchSite,
    pub cave_va: u64,
    pub cave_offset: u64,
    pub jmp: [u8; NEAR_JMP_SIZE],
    payload_len: usize,
    slot: Vec<u8>,
}

impl PlannedPatch {
    pub fn payload(&self) -> &[u8] {
        &self.slot[..self.payload_len]
    }

    pub fn slot_size(&self) -> usize {
        self.slot.len()
    }
}

pub struct PatchPlan {
    segment: PatchSegmentPlan,
    patches: Vec<PlannedPatch>,
    cave_size: u64,
}

impl PatchPlan {
    pub fn segment(&self) -> &PatchSegmentPlan {
        &self.segment
    }

    pub fn patches(&self) -> &[PlannedPatch] {
        &self.patches
    }

    pub fn prepare(
        elf: &ElfFile,
        addrs: &[u64],
        sources: &[String],
        mut assemble: impl FnMut(&str, u64) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        if addrs.len() != sources.len() {
            bail!("patch site and payload counts differ");
        }

        let segment = elf.plan_patch_segment().context("planning patch segment")?;
        let sites = decode_sites(elf, addrs).context("decoding patch sites")?;
        let mut patches = Vec::with_capacity(sites.len());
        let mut cave_va = segment.cave_va;

        // A slot only depends on the lengths of the preceding slots.
        for (site, source) in sites.into_iter().zip(sources) {
            let mut slot = assemble(source, cave_va).context("assembling patch payloads")?;
            let payload_len = slot.len();
            let size = align_up(payload_len as u64 + NEAR_JMP_SIZE as u64, 16)?;
            let next_va = cave_va.checked_add(size).context("cave layout overflow")?;
            let cave_offset = segment
                .file_offset
                .checked_add(cave_va - segment.vaddr)
                .context("cave file offset overflow")?;

            let jmp = encode_jmp(site.addr, cave_va)?;
            let resume_va = site.addr + site.original_bytes.len() as u64;
            let back = encode_jmp(cave_va + payload_len as u64, resume_va)?;
            slot.extend_from_slice(&back);
            slot.resize(size as usize, 0x90);

            patches.push(PlannedPatch {
                site,
                cave_va,
                cave_offset,
                jmp,
                payload_len,
                slot,
            });
            cave_va = next_va;
        }

        Ok(Self {
            cave_size: cave_va - segment.cave_va,
            segment,
            patches,
        })
    }

    /// Apply to the same ELF image used for planning.
    pub fn apply(&self, elf: &mut ElfFile) -> Result<LoadSegment> {
        let segment = elf.install_patch_segment(&self.segment, self.cave_size)?;
        for p in &self.patches {
            let cave = p.cave_offset as usize;
            let site = p.site.file_offset as usize;
            elf.write_bytes(cave..cave + p.slot.len(), &p.slot)?;
            elf.write_bytes(site..site + p.jmp.len(), &p.jmp)?;
        }
        Ok(segment)
    }
}
