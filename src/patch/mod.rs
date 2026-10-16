mod apply;
mod jmp;
mod layout;
mod site;
#[cfg(test)]
mod tests;

pub use apply::apply_patches;
pub use jmp::{NEAR_JMP_SIZE, encode_jmp};
pub use layout::{assemble_in_cave, slot_size};
pub use site::{PatchSite, decode_sites};

/// Per-patch outcome, reported after a successful apply.
pub struct PatchOutcome {
    pub jmp_addr: u64,
    pub jmp_bytes: Vec<u8>,
    pub cave_va: u64,
    pub cave_offset: u64,
    pub cave_size: u64,
    pub overwritten_len: usize,
    pub original_bytes: Vec<u8>,
    pub overwritten_instructions: Vec<(u64, usize)>,
}

/// Result of applying one or more patches sharing a single new segment.
pub struct PatchResult {
    pub patches: Vec<PatchOutcome>,
    pub segment_offset: u64,
    pub segment_vaddr: u64,
    pub segment_size: u64,
}
