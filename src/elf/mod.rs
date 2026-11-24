use anyhow::{Context, Result, bail};
use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;
use std::ops::Range;
use std::path::Path;

mod install;
mod layout;
mod plt;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::synthetic_elf;

pub use layout::{PatchSegmentPlan, align_up};

/// Alignment used for the new `PT_LOAD` segment. ELF requires
/// `p_vaddr % p_align == p_offset % p_align` for loadable segments.
pub const PAGE_SIZE: u64 = 0x1000;

const ELF64_PHENTSIZE: usize = 56;
const ELF64_SHENTSIZE: usize = 64;

// ELF64 header field offsets.
const E_PHOFF: usize = 0x20;
const E_SHOFF: usize = 0x28;
const E_PHNUM: usize = 0x38;
const E_SHNUM: usize = 0x3c;

// ELF64 program header field offsets.
const P_TYPE: usize = 0x00;
const P_FLAGS: usize = 0x04;
const P_OFFSET: usize = 0x08;
const P_VADDR: usize = 0x10;
const P_PADDR: usize = 0x18;
const P_FILESZ: usize = 0x20;
const P_MEMSZ: usize = 0x28;
const P_ALIGN: usize = 0x30;

// ELF64 section header field offsets.
const SH_NAME: usize = 0x00;
const SH_TYPE: usize = 0x04;
const SH_FLAGS: usize = 0x08;
const SH_ADDR: usize = 0x10;
const SH_OFFSET: usize = 0x18;
const SH_SIZE: usize = 0x20;
const SH_LINK: usize = 0x28;
const SH_INFO: usize = 0x2c;
const SH_ADDRALIGN: usize = 0x30;
const SH_ENTSIZE: usize = 0x38;

const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

/// A loadable segment tracked by this tool.
#[derive(Debug, Clone)]
pub struct LoadSegment {
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
}

pub struct ElfFile {
    data: Vec<u8>,
    pub entry_point: u64,
    pub ph_offset: usize,
    pub ph_entry_size: usize,
    pub ph_count: usize,
    pub sh_offset: usize,
    pub sh_entry_size: usize,
    pub sh_count: usize,
    pub shstrndx: usize,
    pub segments: Vec<LoadSegment>,
}

impl ElfFile {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(data)
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<Self> {
        let elf = Elf::parse(&data).context("parsing ELF")?;

        if !elf.is_64 {
            bail!("only ELF64 is supported");
        }
        if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
            bail!("only x86-64 architecture is supported");
        }

        let header = &elf.header;
        if header.e_phnum == 0xffff {
            bail!("extended program header counts (PN_XNUM) are not supported");
        }
        if header.e_shnum == 0 {
            bail!("extended section header counts are not supported");
        }
        if header.e_shstrndx == 0xffff {
            bail!("extended section name table index (SHN_XINDEX) is not supported");
        }

        let ph_offset = header.e_phoff as usize;
        let ph_entry_size = header.e_phentsize as usize;
        let ph_count = header.e_phnum as usize;
        let sh_offset = header.e_shoff as usize;
        let sh_entry_size = header.e_shentsize as usize;
        let sh_count = header.e_shnum as usize;
        let shstrndx = header.e_shstrndx as usize;

        if ph_entry_size != ELF64_PHENTSIZE {
            bail!("unsupported program header entry size {}", ph_entry_size);
        }
        if sh_entry_size != ELF64_SHENTSIZE {
            bail!("unsupported section header entry size {}", sh_entry_size);
        }
        if shstrndx >= sh_count {
            bail!(
                "invalid e_shstrndx {} (section count {})",
                shstrndx,
                sh_count
            );
        }

        check_range(&data, ph_offset, ph_entry_size * ph_count).context("program header table")?;
        check_range(&data, sh_offset, sh_entry_size * sh_count).context("section header table")?;

        let entry_point = elf.entry;
        let mut segments = Vec::new();
        for ph in elf.program_headers.iter() {
            if ph.p_type == PT_LOAD {
                segments.push(LoadSegment {
                    p_flags: ph.p_flags,
                    p_offset: ph.p_offset,
                    p_vaddr: ph.p_vaddr,
                    p_filesz: ph.p_filesz,
                    p_memsz: ph.p_memsz,
                });
            }
        }
        drop(elf);

        Ok(ElfFile {
            data,
            entry_point,
            ph_offset,
            ph_entry_size,
            ph_count,
            sh_offset,
            sh_entry_size,
            sh_count,
            shstrndx,
            segments,
        })
    }

    pub fn find_segment_by_va(&self, va: u64) -> Option<&LoadSegment> {
        self.segments
            .iter()
            .find(|s| va >= s.p_vaddr && va < s.p_vaddr + s.p_memsz)
    }

    /// File offset of a virtual address backed by a loadable segment.
    pub fn va_to_offset(&self, va: u64) -> Result<u64> {
        let seg = self
            .find_segment_by_va(va)
            .with_context(|| format!("no PT_LOAD segment contains VA 0x{:x}", va))?;
        if va >= seg.p_vaddr + seg.p_filesz {
            bail!(
                "VA 0x{:x} lies in the zero-initialised tail of segment VA 0x{:x} and has no file bytes",
                va,
                seg.p_vaddr
            );
        }
        Ok(va - seg.p_vaddr + seg.p_offset)
    }

    /// Exclusive end of the file-backed part of a segment.
    pub fn segment_file_end(&self, seg: &LoadSegment) -> u64 {
        seg.p_offset.saturating_add(seg.p_filesz)
    }

    /// Exclusive end of a segment's virtual address range.
    pub fn segment_va_end(&self, seg: &LoadSegment) -> u64 {
        seg.p_vaddr.saturating_add(seg.p_memsz)
    }

    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Borrow a checked byte range of the underlying image.
    pub fn bytes(&self, range: Range<usize>) -> Result<&[u8]> {
        check_range(&self.data, range.start, range.len())?;
        Ok(&self.data[range])
    }

    /// Overwrite a checked byte range of the underlying image.
    pub fn write_bytes(&mut self, range: Range<usize>, bytes: &[u8]) -> Result<()> {
        if range.len() != bytes.len() {
            bail!(
                "range length {} does not match byte length {}",
                range.len(),
                bytes.len()
            );
        }
        check_range(&self.data, range.start, range.len())?;
        self.data[range].copy_from_slice(bytes);
        Ok(())
    }

    fn read_u64_at(&self, offset: usize) -> Result<u64> {
        check_range(&self.data, offset, 8)?;
        Ok(u64::from_le_bytes(
            self.data[offset..offset + 8].try_into().unwrap(),
        ))
    }

    fn write_u16_at(&mut self, offset: usize, value: u16) -> Result<()> {
        check_range(&self.data, offset, 2)?;
        self.data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn write_u64_at(&mut self, offset: usize, value: u64) -> Result<()> {
        check_range(&self.data, offset, 8)?;
        self.data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, &self.data).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}

fn check_range(data: &[u8], offset: usize, len: usize) -> Result<()> {
    let end = offset.checked_add(len).context("offset overflow")?;
    if end > data.len() {
        bail!(
            "file range 0x{:x}..0x{:x} exceeds file size 0x{:x}",
            offset,
            end,
            data.len()
        );
    }
    Ok(())
}
