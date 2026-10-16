use anyhow::{Context, Result};

/// Bytes a near JMP (E9 + rel32) occupies at the patch site.
pub const NEAR_JMP_SIZE: usize = 5;

/// Encode a near JMP (E9 + rel32) from `from` to `to`.
pub fn encode_jmp(from: u64, to: u64) -> Result<Vec<u8>> {
    let relative = to as i128 - (from as i128 + NEAR_JMP_SIZE as i128);
    let offset = i32::try_from(relative).with_context(|| {
        format!(
            "JMP from 0x{:x} to 0x{:x} is out of rel32 range (delta {})",
            from, to, relative
        )
    })?;

    let mut buf = [0u8; NEAR_JMP_SIZE];
    buf[0] = 0xE9;
    buf[1..5].copy_from_slice(&offset.to_le_bytes());
    Ok(buf.to_vec())
}
