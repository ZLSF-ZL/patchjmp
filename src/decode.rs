use anyhow::{bail, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction};

pub struct DecodedPatch {
    pub bytes: Vec<u8>,
    pub total_len: usize,
    pub instructions: Vec<Instruction>,
}

/// Decode instructions at the patch site and return complete instructions
/// that need to be overwritten. Never splits an instruction.
pub fn decode_patch_site(code: &[u8], base_va: u64, jmp_size: usize) -> Result<DecodedPatch> {
    let mut decoder = Decoder::with_ip(64, code, base_va, DecoderOptions::NONE);
    let mut total_len: usize = 0;
    let mut instructions = Vec::new();

    while decoder.can_decode() && total_len < jmp_size {
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);
        total_len += instr.len();
        instructions.push(instr);
    }

    if total_len < jmp_size {
        bail!(
            "not enough bytes at 0x{:x} to place {}-byte JMP (only decoded {} bytes)",
            base_va,
            jmp_size,
            total_len
        );
    }

    let bytes = code[..total_len].to_vec();
    Ok(DecodedPatch {
        bytes,
        total_len,
        instructions,
    })
}
