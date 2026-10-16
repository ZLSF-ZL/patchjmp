use anyhow::{Context, Result};
use goblin::elf::program_header::{PF_R, PF_X, PT_LOAD, PT_PHDR};

use super::{
    E_PHNUM, E_PHOFF, E_SHNUM, E_SHOFF, ElfFile, LoadSegment, P_ALIGN, P_FILESZ, P_FLAGS, P_MEMSZ,
    P_OFFSET, P_PADDR, P_TYPE, P_VADDR, PAGE_SIZE, PatchSegmentPlan, SH_ADDR, SH_ADDRALIGN,
    SH_ENTSIZE, SH_FLAGS, SH_INFO, SH_LINK, SH_NAME, SH_OFFSET, SH_SIZE, SH_TYPE, SHF_ALLOC,
    SHF_EXECINSTR, SHT_PROGBITS, align_up, check_range,
};

impl ElfFile {
    /// Install the planned segment: write the relocated program header table,
    /// append a `.patch` section header, regenerate `.shstrtab` and update the
    /// ELF header. Existing segments and permissions are not modified.
    pub fn install_patch_segment(
        &mut self,
        plan: &PatchSegmentPlan,
        cave_size: u64,
    ) -> Result<LoadSegment> {
        let cave_size = align_up(cave_size.max(1), 16)?;
        let segment_filesz = plan
            .cave_offset_in_segment
            .checked_add(cave_size)
            .context("patch segment size overflow")?;
        let segment_end = plan
            .file_offset
            .checked_add(segment_filesz)
            .context("patch segment file offset overflow")?;

        let old_shstrtab = self.read_shstrtab()?;
        let mut new_shstrtab = old_shstrtab.clone();
        if new_shstrtab.is_empty() {
            new_shstrtab.push(0);
        }
        let patch_name_index = new_shstrtab.len() as u32;
        new_shstrtab.extend_from_slice(b".patch\0");

        let shstrtab_offset = align_up(segment_end, 8)?;
        let shstrtab_end = shstrtab_offset
            .checked_add(new_shstrtab.len() as u64)
            .context("shstrtab offset overflow")?;
        let new_sht_offset = align_up(shstrtab_end, 8)?;
        let new_sht_size = ((self.sh_count + 1) * self.sh_entry_size) as u64;
        let required = new_sht_offset
            .checked_add(new_sht_size)
            .context("section header table overflow")?;
        self.data.resize(required as usize, 0);

        // --- Relocated program header table --------------------------------
        let entry = self.ph_entry_size;
        let mut pht = vec![0u8; plan.pht_size as usize];
        for i in 0..self.ph_count {
            let src = self.ph_offset + i * entry;
            pht[i * entry..(i + 1) * entry].copy_from_slice(&self.data[src..src + entry]);
        }

        let mut new_entry = vec![0u8; entry];
        set_u32(&mut new_entry, P_TYPE, PT_LOAD);
        set_u32(&mut new_entry, P_FLAGS, PF_R | PF_X);
        set_u64(&mut new_entry, P_OFFSET, plan.file_offset);
        set_u64(&mut new_entry, P_VADDR, plan.vaddr);
        set_u64(&mut new_entry, P_PADDR, plan.vaddr);
        set_u64(&mut new_entry, P_FILESZ, segment_filesz);
        set_u64(&mut new_entry, P_MEMSZ, segment_filesz);
        set_u64(&mut new_entry, P_ALIGN, PAGE_SIZE);
        pht[plan.ph_index * entry..(plan.ph_index + 1) * entry].copy_from_slice(&new_entry);

        // Retarget PT_PHDR (if any) at the relocated table.
        for i in 0..self.ph_count {
            let base = i * entry;
            let p_type =
                u32::from_le_bytes(pht[base + P_TYPE..base + P_TYPE + 4].try_into().unwrap());
            if p_type != PT_PHDR {
                continue;
            }
            set_u32(&mut pht, base + P_FLAGS, PF_R);
            set_u64(
                &mut pht,
                base + P_OFFSET,
                plan.file_offset + plan.pht_offset_in_segment,
            );
            set_u64(
                &mut pht,
                base + P_VADDR,
                plan.vaddr + plan.pht_offset_in_segment,
            );
            set_u64(
                &mut pht,
                base + P_PADDR,
                plan.vaddr + plan.pht_offset_in_segment,
            );
            set_u64(&mut pht, base + P_FILESZ, plan.pht_size);
            set_u64(&mut pht, base + P_MEMSZ, plan.pht_size);
            set_u64(&mut pht, base + P_ALIGN, 8);
        }

        let pht_dst = (plan.file_offset + plan.pht_offset_in_segment) as usize;
        self.data[pht_dst..pht_dst + pht.len()].copy_from_slice(&pht);

        // --- Relocated section header table --------------------------------
        let mut sht = vec![0u8; new_sht_size as usize];
        for i in 0..self.sh_count {
            let src = self.sh_offset + i * self.sh_entry_size;
            sht[i * self.sh_entry_size..(i + 1) * self.sh_entry_size]
                .copy_from_slice(&self.data[src..src + self.sh_entry_size]);
        }

        let shstr_base = self.shstrndx * self.sh_entry_size;
        set_u64(&mut sht, shstr_base + SH_OFFSET, shstrtab_offset);
        set_u64(&mut sht, shstr_base + SH_SIZE, new_shstrtab.len() as u64);

        let patch_base = self.sh_count * self.sh_entry_size;
        set_u32(&mut sht, patch_base + SH_NAME, patch_name_index);
        set_u32(&mut sht, patch_base + SH_TYPE, SHT_PROGBITS);
        set_u64(&mut sht, patch_base + SH_FLAGS, SHF_ALLOC | SHF_EXECINSTR);
        set_u64(&mut sht, patch_base + SH_ADDR, plan.cave_va);
        set_u64(
            &mut sht,
            patch_base + SH_OFFSET,
            plan.file_offset + plan.cave_offset_in_segment,
        );
        set_u64(&mut sht, patch_base + SH_SIZE, cave_size);
        set_u32(&mut sht, patch_base + SH_LINK, 0);
        set_u32(&mut sht, patch_base + SH_INFO, 0);
        set_u64(&mut sht, patch_base + SH_ADDRALIGN, 16);
        set_u64(&mut sht, patch_base + SH_ENTSIZE, 0);

        let shstrtab_dst = shstrtab_offset as usize;
        self.data[shstrtab_dst..shstrtab_dst + new_shstrtab.len()].copy_from_slice(&new_shstrtab);

        let sht_dst = new_sht_offset as usize;
        self.data[sht_dst..sht_dst + sht.len()].copy_from_slice(&sht);

        // --- ELF header -----------------------------------------------------
        self.write_u64_at(E_PHOFF, plan.file_offset)?;
        self.write_u16_at(E_PHNUM, (self.ph_count + 1) as u16)?;
        self.write_u64_at(E_SHOFF, new_sht_offset)?;
        self.write_u16_at(E_SHNUM, (self.sh_count + 1) as u16)?;

        self.ph_offset = plan.file_offset as usize;
        self.ph_count += 1;
        self.sh_offset = new_sht_offset as usize;
        self.sh_count += 1;

        let seg = LoadSegment {
            p_flags: PF_R | PF_X,
            p_offset: plan.file_offset,
            p_vaddr: plan.vaddr,
            p_filesz: segment_filesz,
            p_memsz: segment_filesz,
        };
        self.segments.push(seg.clone());
        Ok(seg)
    }

    fn read_shstrtab(&self) -> Result<Vec<u8>> {
        let base = self.sh_offset + self.shstrndx * self.sh_entry_size;
        let offset = self.read_u64_at(base + SH_OFFSET)? as usize;
        let size = self.read_u64_at(base + SH_SIZE)? as usize;
        check_range(&self.data, offset, size).context("shstrtab")?;
        Ok(self.data[offset..offset + size].to_vec())
    }
}

fn set_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn set_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
