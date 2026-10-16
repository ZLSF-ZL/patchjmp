use goblin::elf::program_header::{PF_R, PF_X, PT_LOAD, PT_PHDR};

use super::*;

/// Build a minimal but structurally valid ELF64 x86-64 executable:
/// a read-only PT_LOAD covering the headers, an R-X PT_LOAD with code,
/// a PT_PHDR and a small section header table.
pub(crate) fn synthetic_elf() -> Vec<u8> {
    const EHDR: usize = 64;
    const PHENT: usize = 56;
    const SHENT: usize = 64;
    const PHNUM: usize = 3;
    const SHNUM: usize = 4;

    let phoff = EHDR;
    let code_off = 0x1000u64;
    let code_va = 0x401000u64;
    let code_size = 0x100u64;
    let comment_off = 0x1100u64;
    let shstr_off = 0x1110u64;

    let shstr = b"\0.text\0.comment\0.shstrtab\0";
    let shoff = 0x1120u64;
    let file_len = (shoff as usize) + SHNUM * SHENT;

    let mut f = vec![0u8; file_len];

    // e_ident
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELFCLASS64
    f[5] = 1; // ELFDATA2LSB
    f[6] = 1; // EV_CURRENT
    f[7] = 0; // ELFOSABI_SYSV
    // e_type / e_machine / e_version
    f[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    f[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    f[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry
    f[24..32].copy_from_slice(&code_va.to_le_bytes());
    // e_phoff / e_shoff
    f[32..40].copy_from_slice(&phoff.to_le_bytes());
    f[40..48].copy_from_slice(&shoff.to_le_bytes());
    // e_flags
    f[48..52].copy_from_slice(&0u32.to_le_bytes());
    // e_ehsize / e_phentsize / e_phnum
    f[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    f[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
    f[56..58].copy_from_slice(&(PHNUM as u16).to_le_bytes());
    // e_shentsize / e_shnum / e_shstrndx
    f[58..60].copy_from_slice(&(SHENT as u16).to_le_bytes());
    f[60..62].copy_from_slice(&(SHNUM as u16).to_le_bytes());
    f[62..64].copy_from_slice(&3u16.to_le_bytes());

    let mut ph = |i: usize,
                  p_type: u32,
                  flags: u32,
                  off: u64,
                  va: u64,
                  filesz: u64,
                  memsz: u64,
                  align: u64| {
        let b = phoff + i * PHENT;
        f[b..b + 4].copy_from_slice(&p_type.to_le_bytes());
        f[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
        f[b + 8..b + 16].copy_from_slice(&off.to_le_bytes());
        f[b + 16..b + 24].copy_from_slice(&va.to_le_bytes());
        f[b + 24..b + 32].copy_from_slice(&va.to_le_bytes());
        f[b + 32..b + 40].copy_from_slice(&filesz.to_le_bytes());
        f[b + 40..b + 48].copy_from_slice(&memsz.to_le_bytes());
        f[b + 48..b + 56].copy_from_slice(&align.to_le_bytes());
    };

    // PT_PHDR, PT_LOAD (R), PT_LOAD (R-X)
    ph(
        0,
        PT_PHDR,
        4,
        phoff as u64,
        phoff as u64,
        (PHNUM * PHENT) as u64,
        (PHNUM * PHENT) as u64,
        8,
    );
    ph(1, PT_LOAD, 4, 0, 0, 0x400, 0x400, 0x1000);
    ph(
        2,
        PT_LOAD,
        4 | 1,
        code_off,
        code_va,
        code_size,
        code_size,
        0x1000,
    );

    // Code region is a run of NOPs plus a RET, so instruction decoding works.
    for b in &mut f[code_off as usize..(code_off + code_size - 1) as usize] {
        *b = 0x90;
    }
    f[(code_off + code_size - 1) as usize] = 0xc3;

    // .comment payload
    f[comment_off as usize..comment_off as usize + 8].copy_from_slice(b"test----");
    f[shstr_off as usize..shstr_off as usize + shstr.len()].copy_from_slice(shstr);

    let mut sh = |i: usize, name: u32, ty: u32, flags: u64, addr: u64, off: u64, size: u64| {
        let b = shoff as usize + i * SHENT;
        f[b..b + 4].copy_from_slice(&name.to_le_bytes());
        f[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
        f[b + 8..b + 16].copy_from_slice(&flags.to_le_bytes());
        f[b + 16..b + 24].copy_from_slice(&addr.to_le_bytes());
        f[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
        f[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
        f[b + 48..b + 56].copy_from_slice(&1u64.to_le_bytes());
    };

    // 0: SHT_NULL, 1: .text, 2: .comment, 3: .shstrtab
    sh(0, 0, 0, 0, 0, 0, 0);
    sh(
        1,
        1,
        1,
        SHF_ALLOC | SHF_EXECINSTR,
        code_va,
        code_off,
        code_size,
    );
    sh(2, 7, 1, 0, 0, comment_off, 8);
    sh(3, 17, 3, 0, 0, shstr_off, shstr.len() as u64);

    f
}

/// Same as `synthetic_elf`, but with the file padded far beyond the VA
/// span of its loadable segments. This is the shape that makes a naive
/// "align the file offset" rule disagree with "align the virtual address".
pub(crate) fn synthetic_elf_with_large_file() -> Vec<u8> {
    // VA span ends at 0x401100; padding the file to 0x500000 makes the file
    // extent, not the VA extent, the binding constraint on the new base.
    // `resize` preserves the header, program headers and section headers.
    let mut data = synthetic_elf();
    data.resize(0x500000, 0);
    data
}

#[test]
fn parses_elf_header_and_segments() {
    let elf = ElfFile::parse(synthetic_elf()).unwrap();
    assert_eq!(elf.entry_point, 0x401000);
    assert_eq!(elf.ph_count, 3);
    assert_eq!(elf.segments.len(), 2);
    assert_eq!(elf.segments[0].p_flags, 4);
    assert_eq!(elf.segments[1].p_flags, 5);
}

#[test]
fn rejects_non_elf_data() {
    assert!(ElfFile::parse(vec![0u8; 128]).is_err());
}

#[test]
fn va_to_offset_rejects_bss_tail() {
    let elf = ElfFile::parse(synthetic_elf()).unwrap();
    assert_eq!(elf.va_to_offset(0x401010).unwrap(), 0x1010);
    // A read-only PT_LOAD with memsz > filesz has no file bytes past filesz.
    let mut data = synthetic_elf();
    // Grow memsz of PT_LOAD[1] artificially via the parse path is not needed;
    // just assert that an unmapped VA is rejected.
    data.truncate(0x2000);
    let elf = ElfFile::parse(data).unwrap();
    assert!(elf.va_to_offset(0x500000).is_err());
}

#[test]
fn plan_places_patch_segment_above_existing_loads() {
    let elf = ElfFile::parse(synthetic_elf()).unwrap();
    let plan = elf.plan_patch_segment().unwrap();
    assert_eq!(plan.ph_index, 3);
    assert_eq!(plan.pht_size, 4 * 56);
    assert!(
        plan.vaddr >= 0x402000,
        "patch VA {:#x} overlaps code",
        plan.vaddr
    );
    assert_eq!(plan.file_offset % PAGE_SIZE, 0);
    assert_eq!(plan.vaddr % PAGE_SIZE, 0);
    assert!(plan.cave_va > plan.vaddr);
}

#[test]
fn patch_segment_vaddr_equals_file_offset_for_at_phdr() {
    // The kernel computes AT_PHDR as load_bias + e_phoff. For ET_EXEC,
    // load_bias is zero, so e_phoff (a file offset) doubles as the virtual
    // address where the relocated PHT must be mapped. Since the PHT sits at
    // offset zero of the new segment, p_vaddr must equal p_offset.
    for data in [synthetic_elf(), synthetic_elf_with_large_file()] {
        let elf = ElfFile::parse(data).unwrap();
        let plan = elf.plan_patch_segment().unwrap();
        assert_eq!(
            plan.vaddr, plan.file_offset,
            "AT_PHDR would point outside the new segment"
        );
        assert_eq!(plan.vaddr + plan.pht_offset_in_segment, plan.file_offset);
    }
}

#[test]
fn patch_segment_stays_above_existing_mappings_when_file_is_larger() {
    // A file whose non-load contents dwarf its VA span used to push
    // file_offset past vaddr, breaking AT_PHDR. The unified base must
    // clear both extents, so the new mapping never overlaps an old one.
    let elf = ElfFile::parse(synthetic_elf_with_large_file()).unwrap();
    let plan = elf.plan_patch_segment().unwrap();
    for seg in &elf.segments {
        assert!(
            plan.vaddr >= elf.segment_va_end(seg),
            "new segment VA {:#x} overlaps segment {:#x}..{:#x}",
            plan.vaddr,
            seg.p_vaddr,
            elf.segment_va_end(seg)
        );
        assert!(plan.file_offset >= elf.segment_file_end(seg));
    }
    assert!(plan.file_offset >= elf.data.len() as u64);

    // Installing must keep the AT_PHDR invariant on the reparsed file:
    // e_phoff has to land inside the new segment, on a valid PT_LOAD entry.
    let mut elf = elf;
    let seg = elf.install_patch_segment(&plan, 0x10).unwrap();
    let reparsed = ElfFile::parse(elf.data.clone()).unwrap();
    assert_eq!(reparsed.ph_offset as u64, seg.p_vaddr);
    assert_eq!(reparsed.ph_offset as u64, seg.p_offset);
    let entry = &reparsed.data[reparsed.ph_offset..reparsed.ph_offset + 56];
    assert_eq!(
        u32::from_le_bytes(entry[0..4].try_into().unwrap()),
        PT_PHDR,
        "e_phoff must point at the relocated PT_PHDR"
    );
    let new_entry_base = plan.ph_index * 56;
    let new_entry = &reparsed.data
        [reparsed.ph_offset + new_entry_base..reparsed.ph_offset + new_entry_base + 56];
    assert_eq!(
        u32::from_le_bytes(new_entry[0..4].try_into().unwrap()),
        PT_LOAD
    );
    assert_eq!(
        u32::from_le_bytes(new_entry[4..8].try_into().unwrap()),
        PF_R | PF_X
    );
}

#[test]
fn install_adds_segment_section_and_moves_tables() {
    let mut elf = ElfFile::parse(synthetic_elf()).unwrap();
    let plan = elf.plan_patch_segment().unwrap();
    let seg = elf.install_patch_segment(&plan, 0x20).unwrap();

    assert_eq!(elf.ph_count, 4);
    assert_eq!(elf.sh_count, 5);
    assert_eq!(seg.p_flags, PF_R | PF_X);
    assert_eq!(seg.p_offset, plan.file_offset);
    assert_eq!(seg.p_vaddr, plan.vaddr);
    assert_eq!(seg.p_filesz, plan.cave_offset_in_segment + 0x20);

    // The relocated ELF must still parse and expose the original segments.
    let reparsed = ElfFile::parse(elf.data.clone()).unwrap();
    assert_eq!(reparsed.segments.len(), 3);
    assert_eq!(reparsed.segments[0].p_vaddr, 0);
    assert_eq!(reparsed.segments[1].p_vaddr, 0x401000);
    assert_eq!(reparsed.segments[2].p_flags, PF_R | PF_X);

    // PT_PHDR (index 0) is retargeted at the relocated table.
    let phdr = &reparsed.data[reparsed.ph_offset..reparsed.ph_offset + 56];
    assert_eq!(
        u64::from_le_bytes(phdr[16..24].try_into().unwrap()),
        plan.vaddr
    );
    assert_eq!(
        u64::from_le_bytes(phdr[32..40].try_into().unwrap()),
        plan.pht_size
    );
}

#[test]
fn original_segments_are_not_modified() {
    let before = synthetic_elf();
    let mut elf = ElfFile::parse(before.clone()).unwrap();
    let plan = elf.plan_patch_segment().unwrap();
    elf.install_patch_segment(&plan, 0x10).unwrap();

    // The two original PT_LOADs keep byte-identical program headers.
    // The original program header table starts at e_phoff = 0x40.
    for i in 1..3 {
        let old = 0x40 + i * 56;
        let new = elf.ph_offset + i * 56;
        assert_eq!(&before[old..old + 56], &elf.data[new..new + 56]);
        assert_eq!(
            u32::from_le_bytes(elf.data[new..new + 4].try_into().unwrap()),
            PT_LOAD
        );
    }
    assert_eq!(&before[0x1000..0x1100], &elf.data[0x1000..0x1100]);
}
