# patchjmp

ELF x64 二进制补丁工具 —— 通过 BSS code cave 技术向任意可执行地址注入自定义代码。

## 简介

patchjmp 是一个纯 Rust 实现的 ELF64 x86-64 二进制补丁工具。它在目标 ELF 文件的 BSS 段中开辟 code cave（代码洞），将用户代码注入其中，然后在目标地址插入一条 JMP 跳转至 cave。整个过程无需重新编译目标程序，且生成的 ELF 结构完整、section header 正确，可直接在 IDA Pro 等反汇编工具中分析。

### 工作原理

1. **指令边界解码** —— 使用 `iced-x86` 解码器在目标地址逐条解码指令，自动找到完整的指令边界，确保不会截断或破坏相邻指令
2. **插入 JMP** —— 在目标地址写入跳转指令（5 字节 rel32 或 14 字节间接跳转），跳转至 BSS 段中的 code cave
3. **构建 code cave** —— cave 内部布局为 `用户 payload` + `JMP 回原地址`，按 8 字节对齐并用 NOP 填充
4. **修复 ELF 结构** —— BSS 段转为 PROGBITS，Section Header Table 及非 load 节整体后移，段标志自动添加 PF_X

```
                    +------------------+
  目标地址:         | JMP → cave       |  (5 或 14 字节)
                    +------------------+
                           |
                           v
                    +------------------+
  BSS code cave:    | 用户 payload     |
                    | JMP back         |  (5 字节，跳回被覆盖区域之后)
                    | NOP 填充         |  (8 字节对齐)
                    +------------------+
```

## 核心功能

### 代码注入
- 在 ELF x64 可执行文件的任意虚拟地址注入自定义代码
- 支持两种输入格式（自动检测）：
  - **x64 汇编**：`xor rax,rax; mov eax,60; syscall`
  - **hex 字节**：`4831c0b83c0000000f05`
- PLT 符号自动解析，汇编中可直接引用外部函数（如 `call _system`）

### 指令边界检测
- 逐条解码目标地址的指令，自动找到完整的指令边界
- 不会截断或破坏相邻指令，被覆盖的原始字节数和内容在输出中明确报告

### 代码重定位
- 被位移的指令自动修复 RIP 相对寻址和相对分支/调用
- 汇编代码在 base 0 处生成，自动重定位到 cave 的实际虚拟地址

### ELF 结构完整性
- BSS 段转为 PROGBITS，cave 数据有正确的 section header 对应
- Section Header Table (SHT) 和非 load 节（.comment, .symtab, .strtab, .shstrtab）整体后移，不与 PT_LOAD 段重叠
- BSS 偏移区域显式填零，保持 BSS 零初始化语义
- PT_LOAD 段的 p_filesz / p_memsz 同步更新，段标志自动添加 PF_X

### BSS 偏移
- `--bss-offset` 选项可跳过 BSS 段开头的 N 字节，避免覆盖栈 canary、TLS 变量等关键数据
- 适用于 BSS 段中已有重要运行时数据的场景

## 安装

```bash
cargo build --release
```

编译产物位于 `target/release/patchjmp`。

## 使用方法

```bash
patchjmp <input> --at <addr> --patch <code> [options]
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `<input>` | 输入 ELF 文件路径 |
| `--at <hex>` | 插入 JMP 的目标虚拟地址 |
| `--patch <code>` | 补丁代码：x64 汇编或 hex 字节（自动检测） |
| `--output <path>` | 输出文件路径（默认：`<input>.patched`） |
| `--bss-offset <hex>` | 跳过 BSS 段开头的 N 字节再放置 cave |
| `-v, --verbose` | 输出详细信息 |

### 示例

```bash
# 注入 exit(1)（汇编格式）
patchjmp ./binary --at 0x401176 --patch "xor rax,rax; mov eax,60; syscall" -v

# 注入 exit(1)（hex 格式）
patchjmp ./binary --at 0x401176 --patch "4831c0b83c0000000f05" -v

# 跳过 BSS 前 0x100 字节（保护 canary/TLS 数据）
patchjmp ./binary --at 0x401176 --patch "nop" --bss-offset 0x100 -v

# 指定输出文件
patchjmp ./binary --at 0x401176 --patch "ret" -o ./patched_binary

# 通过 PLT 调用外部函数
patchjmp ./binary --at 0x401176 --patch "lea rdi,[rip+msg]; call _system" -v
```

### 输出示例

```
=== Patch Summary ===
  JMP site:       0x401176
  JMP bytes:      [e9, 8a, 00, 20, 00]
  Overwritten:    6 bytes (original: [48, 89, e5, 48, 83, ec])
  Code cave:      0x602080 (file offset 0x80)
  Cave size:      16 bytes
  Output:         ./binary.patched
```

## 注意事项

- 仅支持 ELF64 x86-64 格式
- 目标地址必须位于可执行的 PT_LOAD 段内
- 被位移的指令中，若相对跳转超出 rel32 范围将报错
- 工具不会自动恢复被覆盖的原始指令；如需保留原始逻辑，用户需在 payload 中手动处理

## 依赖

| 依赖 | 用途 |
|------|------|
| `goblin` | ELF 文件解析 |
| `clap` | 命令行参数解析 |
| `anyhow` | 错误处理 |
| `iced-x86` | x86-64 指令解码与编码 |
| `asm-rs` | x64 汇编器（纯 Rust） |

## 项目结构

```
src/
├── main.rs    # CLI 入口、payload 解析与代码重定位
├── decode.rs  # 目标地址指令边界解码
├── elf.rs     # ELF 文件读写、段操作、BSS 扩展
└── patch.rs   # 核心补丁逻辑（JMP 编写、cave 构建、段修复）
```
