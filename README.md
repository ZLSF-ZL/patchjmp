# patchjmp

ELF64 x86-64 二进制补丁工具 —— 通过新增独立可执行段注入自定义代码。

## 简介

patchjmp 是一个纯 Rust 实现的 ELF64 x86-64 二进制补丁工具。它**不修改任何原有段**：在文件末尾追加一个专用的 `PT_LOAD` 段（R-X），把用户代码放进去，再在目标地址插入一条 JMP 跳转过去。

整个过程无需重新编译目标程序，原有段的 `p_flags`、`.data`、`.bss` 全部保持原样，生成的 ELF 结构完整、section header 正确，可直接在 IDA Pro 等工具中分析。

### 工作原理

1. **指令边界解码** —— 使用 `iced-x86` 在目标地址逐条解码，自动找到完整指令边界，确保不截断相邻指令
2. **追加独立段** —— 在文件末尾（页对齐）追加一个 `PT_LOAD`，权限固定为 `R-X`，VA 取所有现有 `PT_LOAD` 之后的第一个空闲页
3. **迁移 program header table** —— 新段开头放一份**扩容后的 PHT**（多出新的 `PT_LOAD` 项），`e_phoff` 指向它；`PT_PHDR` 同步重定位。原有段的表项逐字节保持不变
4. **构建 payload** —— 段内布局为 `PHT + 若干个 16 字节对齐的 slot`，每个 slot = `payload + JMP 回原地址 + NOP 填充`；多补丁共用同一个新段，各 payload 依次排列（因 payload 字节数可能取决于其最终 VA，布局会迭代到不动点）
5. **追加 `.patch` 节** —— section header table 扩容并整体迁移到新段之后，`.shstrtab` 重建并追加 `.patch` 名称，原节（含 `.bss` 的 `SHT_NOBITS` 语义）不变

```
                       原有 PT_LOAD 们（flags / filesz / memsz 全部不变）
                       +--------------------------------------+
  ELF 头: e_phoff ───▶ | PT_PHDR + 原有项 + 新增 PT_LOAD(R-X)  |
                       +--------------------------------------+
                                        │
   目标地址:  JMP ───────────────────────┘
     │
     v
                       +--------------------------------------+
   新 PT_LOAD (R-X):   | 重定位后的 PHT                        |
                       | slot #1: payload + JMP back           |
                       | slot #2: payload + JMP back           |
                       | ...                                   |
                       +--------------------------------------+
```

## 核心功能

### 代码注入
- 在 ELF x64 可执行文件的任意可执行地址注入自定义代码
- 支持两种输入格式（自动检测）：
  - **x64 汇编**：`xor rax,rax; mov eax,60; syscall`
  - **hex 字节**：`4831c0b83c0000000f05`
- PLT 符号自动解析（`.plt.sec` 优先，回退到 `.plt`），汇编中可直接引用外部函数（如 `call _puts`）
- **多补丁**：重复 `--at` / `--patch`，第 N 个 `--at` 与第 N 个 `--patch` 一一对应，所有 payload 共用一个新增的 R-X 段（而非每个补丁各加一段）
- **`--dry-run`**：只做全部校验与布局计算并打印将要发生的改动，不写任何文件

### 指令边界检测
- 逐条解码目标地址的指令，自动找到完整边界
- 解码范围被限制在目标地址所在的 `PT_LOAD` 文件区间内，不会跨段覆盖
- 被覆盖的原始字节数和内容在输出中明确报告

### 零侵入的段与节
- **原有 `PT_LOAD` 全部不动**：`p_offset` / `p_vaddr` / `p_filesz` / `p_memsz` / `p_flags` 与补丁前逐字节一致
- **`.data` / `.bss` 不动**：不再需要把 BSS 转成 PROGBITS，也不再有 BSS 被覆盖的问题
- **权限不动**：不把任何原有段改成 RWX，W^X 检查友好
- 新增段固定 `R-X`，只承载代码

### ELF 结构完整性
- program header table 迁移到新段内并扩容，`PT_PHDR` 重定位
- section header table 迁移到文件末尾并扩容，`e_shoff` / `e_shnum` 同步更新
- 新增 `.patch` 节（`SHT_PROGBITS`，`SHF_ALLOC | SHF_EXECINSTR`），`sh_addr` 与段内 VA 一致
- `.shstrtab` 重建并保留全部原有节名

### 汇编即最终地址
- 汇编直接在**最终 cave VA** 上进行，`lea rdi,[rip+msg]`、本地标签、`call` 的 displacement 由汇编器一次算好
- 不再做二次重定位，避免 RIP 相对寻址被改坏
- payload 若含超出 `rel32` 范围的 `call`，会在汇编阶段直接报错，而不是生成错误机器码

## 安装

```bash
cargo build --release
```

产物位于 `target/release/patchjmp`。

## 使用方法

```bash
patchjmp <input> --at <addr> --patch <code> [options]
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `<input>` | 输入 ELF 文件路径 |
| `--at <hex>` | 插入 JMP 的目标虚拟地址；**可重复**，第 N 个 `--at` 与第 N 个 `--patch` 一一对应 |
| `--patch <code>` | 补丁代码：x64 汇编或 hex 字节（自动检测）；可重复以打多个补丁 |
| `--output <path>` | 输出文件路径（默认：`<input>.patched`） |
| `--dry-run` | 只做全部校验与布局计算并打印将要发生的改动，**不写任何文件** |
| `-v, --verbose` | 输出详细信息 |

### 示例

```bash
# 注入 exit(1)（汇编格式）
patchjmp ./binary --at 0x401176 --patch "xor rax,rax; mov eax,60; syscall" -v

# 注入 exit(1)（hex 格式）
patchjmp ./binary --at 0x401176 --patch "4831c0b83c0000000f05" -v

# 指定输出文件
patchjmp ./binary --at 0x401176 --patch "ret" -o ./patched_binary

# 通过 PLT 调用外部函数，并携带内联字符串
patchjmp ./binary --at 0x401176 \
  --patch "lea rdi,[rip+msg]; call _puts; ret; msg: .byte 0x48,0x65,0x6c,0x6c,0x6f,0x00" -v

# 先看看会发生什么，不写文件
patchjmp ./binary --at 0x401176 --patch "ret" --dry-run -v

# 一次打多个补丁：重复 --at/--patch，两者一一对应，
# 所有 payload 共用同一个新增 R-X 段
patchjmp ./binary \
  --at 0x401176 --patch "lea rdi,[rip+a]; call _puts; ret; a: .byte 0x41,0x00" \
  --at 0x401200 --patch "lea rdi,[rip+b]; call _puts; ret; b: .byte 0x42,0x00" -v
```

### 输出示例

单补丁：

```
=== Patch Summary ===
  Patch #1:
    JMP site:       0x1313
    JMP bytes:      [e9, f8, 3f, 00, 00]
    Overwritten:    5 byte(s) across 2 instruction(s) (original: [f3, 0f, 1e, fa, 55])
    Payload:        0x5310 (file offset 0x5310)
    Slot size:      64 bytes
  New PT_LOAD:    0x5000 (file offset 0x5000, 848 bytes, R-X)
  Output:         ./binary.patched
```

多补丁（两个补丁共用一个新段，各自占一个 16 字节对齐的 slot）：

```
=== Patch Summary ===
  Patch #1:
    JMP site:       0x1313
    JMP bytes:      [e9, f8, 3f, 00, 00]
    Overwritten:    5 byte(s) across 2 instruction(s) (original: [f3, 0f, 1e, fa, 55])
    Payload:        0x5310 (file offset 0x5310)
    Slot size:      48 bytes
  Patch #2:
    JMP site:       0x12d5
    JMP bytes:      [e9, 66, 40, 00, 00]
    Overwritten:    5 byte(s) across 2 instruction(s) (original: [f3, 0f, 1e, fa, 55])
    Payload:        0x5340 (file offset 0x5340)
    Slot size:      32 bytes
  New PT_LOAD:    0x5000 (file offset 0x5000, 864 bytes, R-X)
  Output:         ./binary.patched
```

加 `-v` 后还会逐条列出每个补丁点被覆盖的指令及其原始字节、汇编出的 payload 字节；
`--dry-run` 输出：

```
=== Dry Run (nothing written) ===
  Patch #1:  0x1313 -> cave 0x5310 (payload 3 bytes, slot 16 bytes)
  Patch #2:  0x12d5 -> cave 0x5320 (payload 3 bytes, slot 16 bytes)
  Output would be: ./binary.patched
  No file written (--dry-run).
```

## 注意事项

- 仅支持 ELF64 x86-64 格式
- 目标地址必须位于可执行的 `PT_LOAD` 段内，且是文件背书的区间（不能落在 `.bss` 之类无文件字节的尾部）
- JMP 使用 5 字节 `E9 rel32`；新段 VA 紧邻现有映射，正常情况下必然在 ±2GB 内，超范围会显式报错而不是静默截断
- 工具不会自动恢复被覆盖的原始指令；如需保留原始逻辑，用户需在 payload 中手动处理，末尾会自动跳回被覆盖区域之后
- 不支持 `PN_XNUM` / `SHN_XINDEX` 扩展计数形式
- 多补丁时，各补丁点不能重叠（包含各自被覆盖的完整指令范围），否则会报错
- 补丁点必须位于**可执行** PT_LOAD 内（含 `PF_X`），否则拒绝生成

## 依赖

| 依赖 | 用途 |
|------|------|
| `goblin` | ELF 文件解析 |
| `clap` | 命令行参数解析 |
| `anyhow` | 错误处理 |
| `iced-x86` | x86-64 指令解码与边界检测 |
| `asm-rs` | x64 汇编器（纯 Rust） |

## 项目结构

```
src/
├── main.rs    # CLI 入口、verbose/摘要输出
├── payload.rs # --patch 解析（hex / 汇编），按最终地址汇编
├── decode.rs  # 目标地址指令边界解码
├── elf/       # ELF 结构层
│   ├── mod.rs     # ElfFile、parse、查询、save、受检 bytes/write_bytes
│   ├── layout.rs  # plan_patch_segment、对齐与布局计算
│   ├── install.rs # install_patch_segment、PHT/SHT/.shstrtab 写入
│   └── plt.rs     # resolve_plt_symbols
└── patch/     # 补丁语义层
    ├── mod.rs     # PatchOutcome / PatchResult、对外重导出
    ├── jmp.rs     # encode_jmp（E9 rel32）、NEAR_JMP_SIZE
    ├── site.rs    # 补丁点解码、PF_X 校验、重叠检测
    ├── layout.rs  # slot 布局与不动点迭代（assemble_in_cave）
    └── apply.rs   # install 新段 + 写入 payload/双向 JMP
```

各层职责：`main` 只做参数解析与展示，`payload` 负责用户代码到机器码，
`patch` 负责补丁语义（接收 `main` 预算好的段布局，不再自行推导；内部再按 jmp/site/layout/apply 分层），
`elf` 负责 ELF 结构读写并通过受检的 `bytes` / `write_bytes` 对外提供访问。

## 测试

```bash
cargo test        # 23 个单元测试
cargo clippy --all-targets -- -D warnings
```

单元测试使用程序内构造的最小 ELF，不依赖外部样本，覆盖：

- ELF 解析、补丁段规划/安装、PHT/SHT 迁移
- 原有 `PT_LOAD` 不被修改（逐字节比对）、`AT_PHDR` 不变量
- 指令边界解码、JMP 编码边界与超范围拒绝
- 补丁点重叠拒绝、非可执行段拒绝
- 多 payload 的 slot 布局与不动点迭代、多补丁共用单一新段

### 真实运行验证

在 x86_64 Linux（Ubuntu 24.04）上对 `test/` 下的样本做过端到端实测：

- `writer`：在 `menu` 入口打补丁打印 `your_money`，运行输出与原程序逐行 diff 仅多出新增那一行
- `death_note`：一次打 3 个补丁（`welcome` / `menu` / `show_name`），均正常触发，程序退出码为 0
- 其中 `menu` 的 payload 用 `mov esi,[rip+X]` 读取全局变量 `flag`；实测中 `flag` 从 0 变为 1 后补丁输出随之改变，证明 payload 的 RIP 相对寻址基址计算正确
