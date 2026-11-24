use super::{PatchPlan, jmp::encode_jmp, site::decode_sites};
use crate::elf::{ElfFile, synthetic_elf};

#[test]
fn encodes_forward_jmp() {
    // From 0x1000, a 5-byte E9 to 0x2000 => rel32 = 0xffb.
    let b = encode_jmp(0x1000, 0x2000).unwrap();
    assert_eq!(b[0], 0xe9);
    assert_eq!(i32::from_le_bytes(b[1..5].try_into().unwrap()), 0xffb);
}

#[test]
fn encodes_backward_jmp() {
    let b = encode_jmp(0x2000, 0x1000).unwrap();
    assert_eq!(i32::from_le_bytes(b[1..5].try_into().unwrap()), -0x1005);
}

#[test]
fn rejects_out_of_range_jmp() {
    assert!(encode_jmp(0x1000, 0x1_0000_0000).is_err());
    assert!(encode_jmp(0x1_0000_0000, 0x1000).is_err());
}

#[test]
fn rejects_patch_into_non_executable_segment() {
    let elf = ElfFile::parse(synthetic_elf()).unwrap();
    // 0x0..0x400 is the read-only PT_LOAD covering the headers.
    let err = decode_sites(&elf, &[0x100]).unwrap_err();
    assert!(err.to_string().contains("not in an executable segment"));
}

#[test]
fn rejects_overlapping_sites() {
    let elf = ElfFile::parse(synthetic_elf()).unwrap();
    // Each little nop window covers 5 bytes; 0x401000 and 0x401002 overlap.
    let err = decode_sites(&elf, &[0x401000, 0x401002]).unwrap_err();
    assert!(err.to_string().contains("overlap"));
}

#[test]
fn assembles_once_at_final_slot_addresses() {
    let elf = ElfFile::parse(synthetic_elf()).unwrap();
    let sites = [0x401000, 0x401010, 0x401020];
    let sources = ["12".into(), "11".into(), "0".into()];
    let mut assembled_at = Vec::new();
    let plan = PatchPlan::prepare(&elf, &sites, &sources, |source, va| {
        assembled_at.push(va);
        Ok(vec![0x90; source.parse()?])
    })
    .unwrap();

    let base = plan.segment().cave_va;
    assert_eq!(assembled_at, [base, base + 32, base + 48]);
    let sizes: Vec<_> = plan.patches().iter().map(|p| p.slot_size()).collect();
    assert_eq!(sizes, [32, 16, 16]);
}

#[test]
fn rejects_out_of_range_jump_during_planning() {
    let mut elf = ElfFile::parse(synthetic_elf()).unwrap();
    // Push the new segment beyond rel32 reach without growing the fixture file.
    elf.segments[1].p_memsz = 1 << 32;
    let err = PatchPlan::prepare(&elf, &[0x401000], &["nop".into()], |_, _| Ok(vec![0x90]))
        .err()
        .unwrap();
    assert!(err.to_string().contains("out of rel32 range"));
}

#[test]
fn applies_two_patches_into_a_single_segment() {
    let mut elf = ElfFile::parse(synthetic_elf()).unwrap();
    // A seven-byte instruction must be skipped whole, even though the JMP uses five bytes.
    elf.write_bytes(0x1000..0x1007, &[0x48, 0x8d, 0x05, 0, 0, 0, 0])
        .unwrap();
    let plan = PatchPlan::prepare(
        &elf,
        &[0x401000, 0x401010],
        &["6".into(), "20".into()],
        |source, _| Ok(vec![0x90; source.parse()?]),
    )
    .unwrap();
    let segment = plan.apply(&mut elf).unwrap();

    assert_eq!(plan.patches().len(), 2);
    assert_eq!(segment.p_vaddr, plan.segment().vaddr);
    for (p, resume_va) in plan.patches().iter().zip([0x401007, 0x401015]) {
        assert!(p.cave_va >= segment.p_vaddr);
        assert!(p.cave_va + p.slot_size() as u64 <= segment.p_vaddr + segment.p_memsz);
        let site = p.site.file_offset as usize;
        assert_eq!(elf.bytes(site..site + p.jmp.len()).unwrap(), p.jmp);
        let start = p.cave_offset as usize;
        let slot = elf.bytes(start..start + p.slot_size()).unwrap();
        let (payload, rest) = slot.split_at(p.payload().len());
        assert_eq!(payload, p.payload());
        let back = encode_jmp(p.cave_va + payload.len() as u64, resume_va).unwrap();
        assert_eq!(&rest[..back.len()], &back);
        assert!(rest[back.len()..].iter().all(|&b| b == 0x90));
    }
    let reparsed = ElfFile::parse(elf.as_bytes().to_vec()).unwrap();
    assert_eq!(reparsed.segments.len(), 3);
}
