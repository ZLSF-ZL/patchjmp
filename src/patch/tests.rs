use super::*;
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
fn slot_sizes_are_16_byte_aligned() {
    assert_eq!(slot_size(0).unwrap(), 16);
    assert_eq!(slot_size(11).unwrap(), 16);
    assert_eq!(slot_size(12).unwrap(), 32);
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
fn assembles_multiple_payloads_at_distinct_slots() {
    let sources = vec!["nop".to_string(), "nop; nop".to_string()];
    let payloads = assemble_in_cave(0x10000, &sources, |_, src, va| {
        let mut out = Vec::new();
        // encode the base address so the test can see which slot was used
        out.extend_from_slice(&(va as u32).to_le_bytes());
        out.extend_from_slice(src.as_bytes());
        Ok(out)
    })
    .unwrap();
    assert_eq!(payloads.len(), 2);
    let s0 = payloads[0].len();
    let expect_second = 0x10000u64 + slot_size(s0).unwrap();
    assert_eq!(
        u32::from_le_bytes(payloads[1][..4].try_into().unwrap()) as u64,
        expect_second
    );
}

#[test]
fn applies_two_patches_into_a_single_segment() {
    let mut elf = ElfFile::parse(synthetic_elf()).unwrap();
    let plan = elf.plan_patch_segment().unwrap();
    let sites = decode_sites(&elf, &[0x401000, 0x401010]).unwrap();
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0].overwrite_len, 5);

    let payloads = vec![vec![0x90u8; 6], vec![0x90u8; 20]];
    let result = apply_patches(&mut elf, &plan, &sites, &payloads).unwrap();

    assert_eq!(result.patches.len(), 2);
    assert_eq!(result.segment_vaddr, plan.vaddr);
    // both payloads live in the one new segment
    for p in &result.patches {
        assert!(p.cave_va >= plan.vaddr);
        assert!(p.cave_va + p.cave_size <= plan.vaddr + result.segment_size);
        assert_eq!(p.jmp_bytes[0], 0xe9);
    }
    // distinct, non-overlapping slots
    assert!(result.patches[0].cave_va < result.patches[1].cave_va);

    let image = elf.bytes(0..elf.len()).unwrap().to_vec();
    let reparsed = ElfFile::parse(image).unwrap();
    assert_eq!(reparsed.segments.len(), 3);
}
