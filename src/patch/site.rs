use anyhow::{Context, Result, bail};

use crate::decode::decode_patch_site;
use crate::elf::ElfFile;

use super::NEAR_JMP_SIZE;

/// One decoded patch site.
#[derive(Debug, Clone)]
pub struct PatchSite {
    /// Virtual address the injected JMP is placed at.
    pub addr: u64,
    /// File offset backing `addr`.
    pub file_offset: u64,
    /// Number of bytes overwritten (always whole instructions).
    pub overwrite_len: usize,
    /// Original bytes that the JMP overwrites.
    pub original_bytes: Vec<u8>,
    /// `(ip, len)` of every instruction overwritten at the patch site.
    pub instructions: Vec<(u64, usize)>,
}

/// Decode the whole instructions a 5-byte JMP would overwrite at `addr`.
fn decode_site(elf: &ElfFile, addr: u64) -> Result<PatchSite> {
    let seg = elf
        .find_segment_by_va(addr)
        .with_context(|| format!("no PT_LOAD segment contains VA 0x{:x}", addr))?
        .clone();

    if seg.p_flags & goblin::elf::program_header::PF_X == 0 {
        bail!(
            "patch address 0x{:x} is not in an executable segment (flags 0x{:x})",
            addr,
            seg.p_flags
        );
    }

    let file_offset = elf.va_to_offset(addr)?;
    let seg_file_end = elf.segment_file_end(&seg);
    if file_offset >= seg_file_end {
        bail!("patch address 0x{:x} has no file bytes", addr);
    }

    let code = elf.bytes(file_offset as usize..seg_file_end as usize)?;
    let decoded = decode_patch_site(code, addr, NEAR_JMP_SIZE)
        .context("decoding instructions at patch site")?;
    let overwrite_len = decoded.total_len();

    if file_offset + overwrite_len as u64 > seg_file_end {
        bail!(
            "decoded {} bytes at 0x{:x} cross the end of the containing PT_LOAD segment",
            overwrite_len,
            addr
        );
    }

    Ok(PatchSite {
        addr,
        file_offset,
        overwrite_len,
        original_bytes: decoded.bytes.clone(),
        instructions: decoded.instructions.iter().map(|i| (i.ip, i.len)).collect(),
    })
}

/// Decode every requested patch site, rejecting overlapping ones.
pub fn decode_sites(elf: &ElfFile, addrs: &[u64]) -> Result<Vec<PatchSite>> {
    let mut sites = Vec::with_capacity(addrs.len());
    for addr in addrs {
        sites.push(decode_site(elf, *addr)?);
    }
    if sites.is_empty() {
        bail!("no patch sites were given");
    }
    reject_overlaps(&sites)?;
    Ok(sites)
}

fn reject_overlaps(sites: &[PatchSite]) -> Result<()> {
    let mut ranges: Vec<(u64, u64)> = sites
        .iter()
        .map(|s| (s.addr, s.addr + s.overwrite_len as u64))
        .collect();
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            bail!(
                "patch sites overlap: 0x{:x}..0x{:x} and 0x{:x}..0x{:x}",
                pair[0].0,
                pair[0].1,
                pair[1].0,
                pair[1].1
            );
        }
    }
    Ok(())
}
