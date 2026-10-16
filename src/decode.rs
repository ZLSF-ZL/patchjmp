use anyhow::{Result, bail};
use iced_x86::{Decoder, DecoderOptions};

/// One complete instruction found at the patch site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub ip: u64,
    pub len: usize,
}

/// Complete instructions that the injected JMP will overwrite.
#[derive(Debug, Clone)]
pub struct DecodedPatch {
    pub bytes: Vec<u8>,
    pub instructions: Vec<DecodedInstruction>,
}

impl DecodedPatch {
    pub fn total_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Decode instructions at the patch site and return every complete
/// instruction that must be overwritten. Never splits an instruction.
pub fn decode_patch_site(code: &[u8], base_va: u64, jmp_size: usize) -> Result<DecodedPatch> {
    let mut decoder = Decoder::with_ip(64, code, base_va, DecoderOptions::NONE);
    let mut total_len: usize = 0;
    let mut instructions = Vec::new();

    while decoder.can_decode() && total_len < jmp_size {
        let instr = decoder.decode();
        total_len += instr.len();
        instructions.push(DecodedInstruction {
            ip: instr.ip(),
            len: instr.len(),
        });
    }

    if total_len < jmp_size {
        bail!(
            "not enough bytes at 0x{:x} to place {}-byte JMP (only decoded {} bytes)",
            base_va,
            jmp_size,
            total_len
        );
    }

    Ok(DecodedPatch {
        bytes: code[..total_len].to_vec(),
        instructions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_past_jmp_size_at_instruction_boundary() {
        // 4-byte endbr64 + 2-byte xor ebp,ebp => need 6 bytes to cover 5.
        let code = [0xf3u8, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x90];
        let d = decode_patch_site(&code, 0x1000, 5).unwrap();
        assert_eq!(d.total_len(), 6);
        assert_eq!(d.instructions.len(), 2);
        assert_eq!(d.instructions[0].ip, 0x1000);
        assert_eq!(d.bytes, vec![0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed]);
    }

    #[test]
    fn errors_when_not_enough_bytes() {
        let code = [0x90u8, 0x90];
        assert!(decode_patch_site(&code, 0x1000, 5).is_err());
    }

    #[test]
    fn never_splits_an_instruction() {
        // A single 7-byte instruction must be taken whole even though 5 suffice.
        let code = [0x48u8, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90];
        let d = decode_patch_site(&code, 0x2000, 5).unwrap();
        assert_eq!(d.total_len(), 7);
    }
}
