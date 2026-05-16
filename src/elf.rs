use anyhow::{bail, Context, Result};
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::Elf;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct LoadSegment {
    pub index: usize,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub _p_align: u64,
}

pub struct ElfFile {
    pub data: Vec<u8>,
    pub entry_point: u64,
    pub ph_offset: usize,
    pub ph_entry_size: usize,
    pub sh_offset: usize,
    pub sh_entry_size: usize,
    pub sh_count: usize,
    pub segments: Vec<LoadSegment>,
}

impl ElfFile {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(data)
    }

    fn parse(data: Vec<u8>) -> Result<Self> {
        let cloned = data.clone();
        let elf = Elf::parse(&cloned).context("parsing ELF")?;

        if !elf.is_64 {
            bail!("only ELF64 is supported");
        }
        if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
            bail!("only x86-64 architecture is supported");
        }

        let header = &elf.header;
        let ph_offset = header.e_phoff as usize;
        let ph_entry_size = header.e_phentsize as usize;
        let sh_offset = header.e_shoff as usize;
        let sh_entry_size = header.e_shentsize as usize;
        let sh_count = header.e_shnum as usize;

        let segments = elf
            .program_headers
            .iter()
            .enumerate()
            .filter(|(_, ph)| ph.p_type == PT_LOAD)
            .map(|(i, ph)| LoadSegment {
                index: i,
                p_flags: ph.p_flags,
                p_offset: ph.p_offset,
                p_vaddr: ph.p_vaddr,
                p_filesz: ph.p_filesz,
                p_memsz: ph.p_memsz,
                _p_align: ph.p_align,
            })
            .collect();

        Ok(ElfFile {
            data,
            entry_point: elf.entry,
            ph_offset,
            ph_entry_size,
            sh_offset,
            sh_entry_size,
            sh_count,
            segments,
        })
    }

    pub fn find_segment_by_va(&self, va: u64) -> Option<&LoadSegment> {
        self.segments
            .iter()
            .find(|s| va >= s.p_vaddr && va < s.p_vaddr + s.p_memsz)
    }

    pub fn va_to_offset(&self, va: u64) -> Result<u64> {
        let seg = self
            .find_segment_by_va(va)
            .with_context(|| format!("no segment contains VA 0x{:x}", va))?;
        Ok(va - seg.p_vaddr + seg.p_offset)
    }

    pub fn write_u32(&mut self, offset: usize, value: u32) {
        self.data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, offset: usize, value: u64) {
        self.data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub fn update_segment(
        &mut self,
        seg: &LoadSegment,
        new_flags: Option<u32>,
        new_filesz: Option<u64>,
        new_memsz: Option<u64>,
    ) -> Result<()> {
        let ph_start = self.ph_offset + seg.index * self.ph_entry_size;

        if let Some(flags) = new_flags {
            self.write_u32(ph_start + 4, flags);
        }
        if let Some(filesz) = new_filesz {
            self.write_u64(ph_start + 32, filesz);
        }
        if let Some(memsz) = new_memsz {
            self.write_u64(ph_start + 40, memsz);
        }

        if let Some(s) = self.segments.iter_mut().find(|s| s.index == seg.index) {
            if let Some(flags) = new_flags {
                s.p_flags = flags;
            }
            if let Some(filesz) = new_filesz {
                s.p_filesz = filesz;
            }
            if let Some(memsz) = new_memsz {
                s.p_memsz = memsz;
            }
        }

        Ok(())
    }


    /// Find the BSS section (SHT_NOBITS with sh_addr inside the segment's VA range).
    fn find_bss_section_in_segment(&self, seg: &LoadSegment) -> Option<usize> {
        for i in 0..self.sh_count {
            let off = self.sh_offset + i * self.sh_entry_size;
            if off + self.sh_entry_size > self.data.len() {
                break;
            }
            let sh_type = u32::from_le_bytes(self.data[off + 4..off + 8].try_into().unwrap());
            let sh_addr = u64::from_le_bytes(self.data[off + 16..off + 24].try_into().unwrap());
            let sh_size = u64::from_le_bytes(self.data[off + 32..off + 40].try_into().unwrap());

            // SHT_NOBITS = 8
            if sh_type == 8 && sh_addr >= seg.p_vaddr && sh_addr < seg.p_vaddr + seg.p_memsz && sh_size > 0 {
                return Some(i);
            }
        }
        None
    }

    /// Convert a BSS (SHT_NOBITS) section to SHT_PROGBITS with file-backed data.
    /// Also updates the cached sh_offset and sh_size.
    fn convert_bss_to_progbits(&mut self, sec_idx: usize, file_offset: u64, file_size: u64) {
        let off = self.sh_offset + sec_idx * self.sh_entry_size;
        // sh_type: offset 4, SHT_PROGBITS = 1
        self.write_u32(off + 4, 1);
        // sh_offset: offset 24
        self.write_u64(off + 24, file_offset);
        // sh_size: offset 32
        self.write_u64(off + 32, file_size);
    }

    /// Create a new SHT_NOBITS section after the last existing section.
    /// Returns the new section index.
    fn create_nobits_section(
        &mut self,
        name_offset: u32,
        addr: u64,
        size: u64,
        flags: u64,
    ) -> usize {
        let new_idx = self.sh_count;
        let entry_off = self.sh_offset + new_idx * self.sh_entry_size;

        // Zero out the entry
        self.data[entry_off..entry_off + self.sh_entry_size].fill(0);

        // sh_name: offset 0
        self.write_u32(entry_off, name_offset);
        // sh_type: offset 4, SHT_NOBITS = 8
        self.write_u32(entry_off + 4, 8);
        // sh_flags: offset 8
        self.write_u64(entry_off + 8, flags);
        // sh_addr: offset 16
        self.write_u64(entry_off + 16, addr);
        // sh_offset: offset 24 (0 for NOBITS)
        self.write_u64(entry_off + 24, 0);
        // sh_size: offset 32
        self.write_u64(entry_off + 32, size);
        // sh_link, sh_info, sh_addralign, sh_entsize: all 0

        self.sh_count += 1;
        new_idx
    }

    /// Shift everything after BSS (SHT + non-load sections) by `shift_amount` bytes.
    ///
    /// Non-load sections: sh_addr=0, sh_size>0 (.comment, .symtab, .strtab, .shstrtab).
    /// Their sh_offset values are updated by `shift_amount`.
    /// The SHT itself is also shifted; e_shoff is updated.
    fn shift_post_bss(&mut self, shift_amount: u64) -> Result<()> {
        if shift_amount == 0 {
            return Ok(());
        }

        // Collect non-load sections (sh_addr=0, sh_size>0)
        let mut nonload_sections: Vec<(usize, u64, u64)> = Vec::new();
        for i in 0..self.sh_count {
            let off = self.sh_offset + i * self.sh_entry_size;
            if off + self.sh_entry_size > self.data.len() {
                break;
            }
            let sh_addr = u64::from_le_bytes(self.data[off + 16..off + 24].try_into().unwrap());
            let sh_offset = u64::from_le_bytes(self.data[off + 24..off + 32].try_into().unwrap());
            let sh_size = u64::from_le_bytes(self.data[off + 32..off + 40].try_into().unwrap());
            if sh_addr == 0 && sh_size > 0 {
                nonload_sections.push((i, sh_offset, sh_size));
            }
        }

        // Read SHT data before any writes
        let old_sht_start = self.sh_offset;
        let sht_size = self.sh_count * self.sh_entry_size;
        let old_sht_end = std::cmp::min(old_sht_start + sht_size, self.data.len());
        let mut sht_data = self.data[old_sht_start..old_sht_end].to_vec();

        // Read non-load section data before buffer expansion
        let mut nonload_data: Vec<(usize, Vec<u8>)> = Vec::new();
        for &(idx, sh_off, sh_size) in &nonload_sections {
            let start = sh_off as usize;
            let end = std::cmp::min((sh_off + sh_size) as usize, self.data.len());
            let bytes = if start < end { self.data[start..end].to_vec() } else { vec![0u8; sh_size as usize] };
            nonload_data.push((idx, bytes));
        }

        // Expand buffer
        let total_nonload: u64 = nonload_data.iter().map(|(_, d)| align_up(d.len() as u64, 8)).sum();
        let needed = (self.sh_offset as u64 + shift_amount + sht_size as u64 + total_nonload + 1024) as usize;
        if needed > self.data.len() {
            self.data.resize(needed, 0);
        }

        // New positions: SHT first, then non-load sections
        let new_sht_start = self.sh_offset as u64 + shift_amount;
        let new_nonload_start = align_up(new_sht_start + sht_size as u64, 8);

        // Update sh_offset in SHT for each non-load section
        let mut current = new_nonload_start;
        for &(idx, ref bytes) in &nonload_data {
            let entry_off = idx * self.sh_entry_size;
            let off_field = entry_off + 24;
            if off_field + 8 <= sht_data.len() {
                sht_data[off_field..off_field + 8].copy_from_slice(&current.to_le_bytes());
            }
            current = align_up(current + bytes.len() as u64, 8);
        }

        // Zero old locations
        for &(_, sh_off, sh_size) in &nonload_sections {
            let start = sh_off as usize;
            let end = std::cmp::min((sh_off + sh_size) as usize, self.data.len());
            if start < end { self.data[start..end].fill(0); }
        }
        if old_sht_start < old_sht_end {
            self.data[old_sht_start..old_sht_end].fill(0);
        }

        // Write non-load sections to new positions
        current = new_nonload_start;
        for (_, bytes) in &nonload_data {
            let start = current as usize;
            self.data[start..start + bytes.len()].copy_from_slice(bytes);
            current = align_up(current + bytes.len() as u64, 8);
        }

        // Write SHT to new position
        let new_sht_usize = new_sht_start as usize;
        self.data[new_sht_usize..new_sht_usize + sht_data.len()].copy_from_slice(&sht_data);

        // Update e_shoff in ELF header (offset 40)
        self.write_u64(40, new_sht_start);
        self.sh_offset = new_sht_start as usize;

        Ok(())
    }

    /// Extend a segment to accommodate a code cave in the BSS region.
    ///
    /// With `bss_offset=0`, the cave starts at the BSS file offset.
    /// With `bss_offset>0`, the first `bss_offset` bytes of BSS are preserved (skipped),
    /// and the cave starts after them. This avoids overwriting important BSS data
    /// (e.g. stack canary, TLS variables).
    ///
    /// Everything after BSS (SHT + non-load sections) is shifted accordingly.
    /// The BSS section header is converted from SHT_NOBITS to SHT_PROGBITS.
    ///
    /// Returns the file offset where the cave begins.
    pub fn extend_segment_for_cave(
        &mut self,
        seg: &LoadSegment,
        cave_size: u64,
        bss_offset: u64,
    ) -> Result<u64> {
        let bss_size = seg.p_memsz.saturating_sub(seg.p_filesz);
        let cave_size_padded = align_up(cave_size, 8).max(8);

        let bss_file_start = seg.p_offset + seg.p_filesz;
        let cave_file_start = bss_file_start + bss_offset;

        // Shift everything after BSS by the amount of new file data inserted
        let shift = bss_offset + cave_size_padded;
        self.shift_post_bss(shift)?;

        // Update segment: p_filesz grows by bss_offset + cave_size_padded
        let new_filesz = seg.p_filesz + bss_offset + cave_size_padded;
        let remaining_bss = bss_size.saturating_sub(bss_offset + cave_size_padded);
        let new_memsz = new_filesz + remaining_bss;
        self.update_segment(seg, None, Some(new_filesz), Some(new_memsz))?;

        // Zero-fill the BSS offset region (preserves BSS zero-init semantics)
        let zero_start = bss_file_start as usize;
        let zero_end = cave_file_start as usize;
        if zero_start < self.data.len() {
            let end = zero_end.min(self.data.len());
            self.data[zero_start..end].fill(0);
        }

        // Convert BSS section to PROGBITS covering the entire new file-backed region
        if let Some(bss_idx) = self.find_bss_section_in_segment(seg) {
            self.convert_bss_to_progbits(bss_idx, bss_file_start, bss_offset + cave_size_padded);
            if remaining_bss > 0 {
                let remaining_bss_va = seg.p_vaddr + new_filesz;
                self.create_nobits_section(0, remaining_bss_va, remaining_bss, 0x3);
            }
        }

        Ok(cave_file_start)
    }

    pub fn ensure_file_size(&mut self) {
        let max_end = self
            .segments
            .iter()
            .map(|s| (s.p_offset + s.p_filesz) as usize)
            .max()
            .unwrap_or(0)
            .max(self.data.len());
        if max_end > self.data.len() {
            self.data.resize(max_end, 0);
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, &self.data)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn resolve_plt_symbols(&self) -> Result<HashMap<String, u64>> {
        let elf = Elf::parse(&self.data).context("re-parsing ELF for PLT symbols")?;
        let mut result = HashMap::new();

        let dynsyms: Vec<_> = elf.dynsyms.iter().collect();

        let mut all_stubs: Vec<u64> = Vec::new();
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if !name.contains("plt") {
                continue;
            }
            let va = sh.sh_addr;
            let size = sh.sh_size as usize;
            let file_off = sh.sh_offset as usize;
            if size == 0 || file_off + size > self.data.len() {
                continue;
            }
            let data = &self.data[file_off..file_off + size];
            let mut i = 0;
            while i + 9 < data.len() {
                if data[i] == 0xF3
                    && data[i + 1] == 0x0F
                    && data[i + 2] == 0x1E
                    && data[i + 3] == 0xFA
                    && data[i + 4] == 0xFF
                    && data[i + 5] == 0x25
                {
                    all_stubs.push(va + i as u64);
                    i += 16;
                } else {
                    i += 1;
                }
            }
        }

        for (i, rel) in elf.pltrelocs.iter().enumerate() {
            if i >= all_stubs.len() {
                break;
            }
            let sym_idx = rel.r_sym as usize;
            if sym_idx < dynsyms.len() {
                let sym = &dynsyms[sym_idx];
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        result.insert(name.to_string(), all_stubs[i]);
                    }
                }
            }
        }

        Ok(result)
    }
}

pub fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}
