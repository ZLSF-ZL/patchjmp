use anyhow::{Context, Result, bail};

use crate::elf::align_up;

use super::NEAR_JMP_SIZE;

/// Upper bound on assemble/layout iterations when resolving payload slots.
const MAX_LAYOUT_PASSES: usize = 8;

/// Bytes reserved for one payload: `payload + back-JMP`, rounded up to 16.
pub fn slot_size(payload_len: usize) -> Result<u64> {
    align_up(payload_len as u64 + NEAR_JMP_SIZE as u64, 16)
}

/// Virtual address of each payload slot inside the cave, given payload sizes.
pub(super) fn slot_addresses(cave_va: u64, sizes: &[usize]) -> Result<Vec<u64>> {
    let mut slots = Vec::with_capacity(sizes.len());
    let mut cursor = cave_va;
    for size in sizes {
        slots.push(cursor);
        cursor = cursor
            .checked_add(slot_size(*size)?)
            .context("cave layout overflow")?;
    }
    Ok(slots)
}

/// Total bytes the cave must reserve for the given payload sizes.
pub fn cave_extent(sizes: &[usize]) -> Result<u64> {
    let mut total = 0u64;
    for size in sizes {
        total = total
            .checked_add(slot_size(*size)?)
            .context("cave layout overflow")?;
    }
    Ok(total)
}

/// Assemble every payload at the virtual address it will finally live at.
///
/// A payload's size can depend on its own base address (a local branch may be
/// encoded rel8 or rel32), and its base address depends on the sizes of the
/// payloads before it. Resolve that by iterating until the sizes stop changing.
pub fn assemble_in_cave<F>(
    cave_va: u64,
    sources: &[String],
    mut assemble: F,
) -> Result<Vec<Vec<u8>>>
where
    F: FnMut(usize, &str, u64) -> Result<Vec<u8>>,
{
    let mut sizes = vec![0usize; sources.len()];

    for _ in 0..MAX_LAYOUT_PASSES {
        let slots = slot_addresses(cave_va, &sizes)?;
        let mut payloads = Vec::with_capacity(sources.len());
        for (i, source) in sources.iter().enumerate() {
            payloads.push(assemble(i, source, slots[i])?);
        }
        let new_sizes: Vec<usize> = payloads.iter().map(Vec::len).collect();
        if new_sizes == sizes {
            return Ok(payloads);
        }
        sizes = new_sizes;
    }

    bail!(
        "payload layout did not converge after {} passes",
        MAX_LAYOUT_PASSES
    )
}
