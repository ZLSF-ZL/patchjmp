use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::collections::HashMap;

use super::ElfFile;

impl ElfFile {
    pub fn resolve_plt_symbols(&self) -> Result<HashMap<String, u64>> {
        let elf = Elf::parse(&self.data).context("re-parsing ELF for PLT symbols")?;
        let mut result = HashMap::new();
        let dynsyms: Vec<_> = elf.dynsyms.iter().collect();

        let section_name = |sh: &goblin::elf::SectionHeader| {
            elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string()
        };

        // Modern toolchains emit `.plt.sec`; older/alternate layouts use `.plt`,
        // where the first entry is the resolver stub rather than a symbol.
        let (plt_sec, stub_base_index) = match elf
            .section_headers
            .iter()
            .find(|sh| section_name(sh) == ".plt.sec")
        {
            Some(sec) => (Some(sec), 0u64),
            None => (
                elf.section_headers
                    .iter()
                    .find(|sh| section_name(sh) == ".plt"),
                1u64,
            ),
        };

        if let Some(sec) = plt_sec {
            let stub_size = 16u64;
            for (i, rel) in elf.pltrelocs.iter().enumerate() {
                let sym_idx = rel.r_sym;
                if sym_idx >= dynsyms.len() {
                    continue;
                }
                let sym = &dynsyms[sym_idx];
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
                    && !name.is_empty()
                {
                    let stub_addr = sec.sh_addr + (i as u64 + stub_base_index) * stub_size;
                    result.entry(name.to_string()).or_insert(stub_addr);
                }
            }
        }

        Ok(result)
    }
}
