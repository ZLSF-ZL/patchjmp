use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use asm_rs::Arch;

/// Parse a `--patch` value into final-position machine code.
///
/// Accepts either hex bytes (`4831c0...`) or x86-64 assembly. Assembly is
/// emitted directly at `base_addr` so RIP-relative operands and local labels
/// resolve to their final virtual addresses without a relocation pass.
pub fn parse_payload(
    source: &str,
    base_addr: u64,
    plt_symbols: &HashMap<String, u64>,
) -> Result<Vec<u8>> {
    let trimmed = source.trim();
    if is_hex_string(trimmed) {
        return parse_hex_bytes(trimmed);
    }

    let labels = plt_labels(plt_symbols);
    let label_refs: Vec<(&str, u64)> = labels
        .iter()
        .map(|(name, addr)| (name.as_str(), *addr))
        .collect();

    let mut asm = asm_rs::Assembler::new(Arch::X86_64);
    asm.base_address(base_addr);
    for &(name, addr) in &label_refs {
        asm.define_external(name, addr);
    }
    asm.emit(trimmed)
        .map_err(|e| anyhow::anyhow!("assembly error: {}", e))
        .context(format!("assembling: {}", trimmed))?;
    let result = asm
        .finish()
        .map_err(|e| anyhow::anyhow!("assembly error: {}", e))
        .context(format!("assembling: {}", trimmed))?;
    Ok(result.into_bytes())
}

/// `0x`-prefixed or bare even-length hex digit string.
fn is_hex_string(s: &str) -> bool {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    !stripped.is_empty()
        && stripped.chars().all(|c| c.is_ascii_hexdigit())
        && stripped.len().is_multiple_of(2)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        bail!(
            "hex string must have even number of characters, got {}",
            s.len()
        );
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .context("invalid hex string")
}

/// Register both the plain name and its underscore form for PLT symbols.
fn plt_labels(plt_symbols: &HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut labels: Vec<(String, u64)> = Vec::new();
    for (name, &addr) in plt_symbols {
        labels.push((name.clone(), addr));
        if !name.starts_with('_') {
            labels.push((format!("_{}", name), addr));
        }
    }
    labels.sort_by(|a, b| a.0.cmp(&b.0));
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_with_and_without_prefix() {
        assert_eq!(parse_hex_bytes("4831c0").unwrap(), vec![0x48, 0x31, 0xc0]);
        assert_eq!(parse_hex_bytes("0x4831c0").unwrap(), vec![0x48, 0x31, 0xc0]);
    }

    #[test]
    fn detects_hex_only_for_even_length_digit_strings() {
        assert!(is_hex_string("4831c0"));
        assert!(is_hex_string("0x4831c0"));
        assert!(!is_hex_string("xor rax, rax"));
        assert!(!is_hex_string("4831c"));
    }

    #[test]
    fn assembles_at_the_final_address() {
        let payload = parse_payload(
            "lea rdi,[rip+msg]; ret; msg: .byte 0x41,0x00",
            0x1000,
            &HashMap::new(),
        )
        .unwrap();
        // 48 8d 3d 01 00 00 00 (lea rdi,[rip+1]); c3 (ret); 41 00 (msg)
        assert_eq!(
            payload,
            vec![0x48, 0x8d, 0x3d, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x41, 0x00]
        );
    }

    #[test]
    fn resolves_plt_label_with_and_without_underscore() {
        let mut plt = HashMap::new();
        plt.insert("puts".to_string(), 0x1050u64);
        assert!(!parse_payload("call puts", 0x2000, &plt).unwrap().is_empty());
        assert!(
            !parse_payload("call _puts", 0x2000, &plt)
                .unwrap()
                .is_empty()
        );
    }
}
