use anyhow::{Context, Result, bail};

use super::{ElfFile, PAGE_SIZE};

/// Deterministic layout of the dedicated patch segment.
#[derive(Debug, Clone)]
pub struct PatchSegmentPlan {
    /// Index the new `PT_LOAD` will occupy in the relocated file header table.
    pub ph_index: usize,
    /// File offset of the new segment (page aligned).
    pub file_offset: u64,
    /// Virtual address of the new segment (page aligned).
    pub vaddr: u64,
    /// Offset of the relocated program header table inside the new segment.
    pub pht_offset_in_segment: u64,
    /// Size in bytes of the relocated program header table.
    pub pht_size: u64,
    /// Offset of the patch payload relative to the new segment.
    pub cave_offset_in_segment: u64,
    /// Virtual address the patch payload will be mapped at.
    pub cave_va: u64,
}

impl ElfFile {
    /// Plan the dedicated patch segment without mutating the file.
    ///
    /// The segment is appended at the end of the file and begins with a copy of
    /// the program header table, which is what lets `e_phnum` grow by one. No
    /// existing segment or permission is touched.
    ///
    /// The new segment's virtual address is deliberately tied to its file
    /// offset. The kernel reports `AT_PHDR = load_bias + e_phoff`, and for an
    /// `ET_EXEC` image `load_bias` is zero, so `e_phoff` -- a *file offset* --
    /// is also the virtual address at which the dynamic linker expects to find
    /// the table. Because the relocated table sits at offset zero of the new
    /// segment, the only layout that keeps `AT_PHDR` pointing at mapped memory
    /// is
    ///
    /// ```text
    /// p_vaddr == e_phoff == file_offset
    /// ```
    ///
    /// Both values are therefore derived from a single page-aligned base that
    /// clears every existing file extent and every existing mapping, which
    /// makes the equality structural rather than incidental.
    pub fn plan_patch_segment(&self) -> Result<PatchSegmentPlan> {
        if self.segments.is_empty() {
            bail!("ELF file has no PT_LOAD segments");
        }
        if self.ph_count >= 0xfffe {
            bail!("program header table is full");
        }

        let mut file_end = self.data.len() as u64;
        let mut vaddr_end = 0u64;
        for seg in &self.segments {
            file_end = file_end.max(self.segment_file_end(seg));
            vaddr_end = vaddr_end.max(self.segment_va_end(seg));
        }

        let base = align_up(file_end.max(vaddr_end), PAGE_SIZE)?.max(PAGE_SIZE);
        let file_offset = base;
        let vaddr = base;

        let pht_size = ((self.ph_count + 1) * self.ph_entry_size) as u64;
        let pht_offset_in_segment = 0u64;
        let cave_offset_in_segment = align_up(pht_size, 16)?;
        let cave_va = vaddr
            .checked_add(cave_offset_in_segment)
            .context("patch virtual address overflow")?;

        Ok(PatchSegmentPlan {
            ph_index: self.ph_count,
            file_offset,
            vaddr,
            pht_offset_in_segment,
            pht_size,
            cave_offset_in_segment,
            cave_va,
        })
    }
}

pub fn align_up(value: u64, align: u64) -> Result<u64> {
    if align == 0 || !align.is_power_of_two() {
        bail!("alignment must be a non-zero power of two, got {}", align);
    }
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .context("alignment overflow")
}
