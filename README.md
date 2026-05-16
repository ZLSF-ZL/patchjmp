# patchjmp

ELF x64 binary patcher — inject custom code into any executable address via BSS code cave technique.

## What is patchjmp

patchjmp 是一个纯 Rust 实现的 ELF64 x86-64 二进制补丁工具。它通过在 BSS 段开辟 code cave 来注入自定义代码，无需重新编译目标程序。

核心思路：在目标地址插入一条 JMP 跳转到 BSS 段中的 code cave，cave 内存放用户代码 + 跳回指令。整个过程对 IDA Pro 等反汇编工具友好——生成的 ELF 结构完整，section header 正确，可直接分析。

## Core Features

### Code Injection
- 在 ELF x64 可执行文件的任意虚拟地址注入自定义代码
- 支持 x64 汇编（如 `xor rax,rax; mov eax,60; syscall`）和 hex 字节（如 `4831c0b83c0000000f05`）两种输入格式，自动检测
- PLT 符号自动解析，汇编中可直接引用外部函数（如 `call _system`）

### Instruction Boundary Detection
- 使用 `iced-x86` 解码器逐条解码目标地址的指令，自动找到完整的指令边界
- 不会截断或破坏相邻指令，被覆盖的原始字节数和内容在输出中明确报告

### Code Relocation
- 被位移的指令自动修复 RIP 相对寻址和相对分支/调用
- 汇编代码在 base 0 处生成，自动重定位到 cave 的实际虚拟地址

### ELF Structure Integrity
- BSS 段转为 PROGBITS，cave 数据有正确的 section header 对应
- Section Header Table (SHT) 和非 load 节（.comment, .symtab, .strtab, .shstrtab）整体后移，不与 PT_LOAD 段重叠
- BSS 偏移区域显式填零，保持 BSS 零初始化语义
- PT_LOAD 段的 p_filesz / p_memsz 同步更新，段标志自动添加 PF_X

### BSS Offset
- `--bss-offset` 选项可跳过 BSS 段开头的 N 字节，避免覆盖栈 canary、TLS 变量等关键数据
- 适用于 BSS 段中已有重要运行时数据的场景

## Install

```bash
cargo build --release
```

## Usage

```bash
patchjmp <input> --at <addr> --patch <code> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<input>` | Input ELF file path |
| `--at <hex>` | Virtual address where the JMP will be placed |
| `--patch <code>` | Patch code: x64 assembly or hex bytes (auto-detected) |
| `--output <path>` | Output file path (default: `<input>.patched`) |
| `--bss-offset <hex>` | Skip N bytes at the start of BSS before placing the cave |
| `-v, --verbose` | Verbose output |

### Examples

```bash
# Inject exit(1) via assembly
patchjmp ./binary --at 0x401176 --patch "xor rax,rax; mov eax,60; syscall" -v

# Inject via hex bytes
patchjmp ./binary --at 0x401176 --patch "4831c0b83c0000000f05" -v

# Skip first 0x100 bytes of BSS (protect canary/TLS data)
patchjmp ./binary --at 0x401176 --patch "nop" --bss-offset 0x100 -v

# Specify output file
patchjmp ./binary --at 0x401176 --patch "ret" -o ./patched_binary

# Call external function via PLT
patchjmp ./binary --at 0x401176 --patch "lea rdi,[rip+msg]; call _system" -v
```

## How It Works

1. **Decode instruction boundaries** — `iced-x86` decoder walks instructions at the target address, accumulating lengths until enough space for a JMP (5-byte near or 14-byte indirect)
2. **Insert JMP** — Write a jump at the target address pointing to the code cave in BSS
3. **Build code cave** — Layout: `payload (user code)` + `JMP back (return to original flow)`, NOP-padded to 8-byte alignment
4. **Fix ELF structure** — Convert BSS section to PROGBITS, shift SHT and non-load sections, update segment sizes and flags

> **Note:** The tool does NOT automatically restore the overwritten original instructions. Users must handle displaced logic in their payload code if needed. This gives full control to the user.

## Cave Layout

```
                    +------------------+
  Target address:   | JMP to cave      |  (5 or 14 bytes)
                    +------------------+
                           |
                           v
                    +------------------+
  BSS code cave:    | User payload     |
                    | JMP back         |  (5 bytes, jumps past overwritten area)
                    | NOP padding      |  (align to 8 bytes)
                    +------------------+
```

## Limitations

- Only supports ELF64 x86-64 format
- Target address must be within an executable PT_LOAD segment
- Displaced instructions with relative jumps exceeding rel32 range will cause an error
- The tool does not restore overwritten instructions automatically

## Dependencies

- `goblin` — ELF parsing
- `clap` — CLI argument parsing
- `anyhow` — Error handling
- `iced-x86` — x86-64 instruction decoding and encoding
- `asm-rs` — x64 assembler (pure Rust, no external dependencies)
