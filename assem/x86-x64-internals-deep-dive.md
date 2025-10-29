# x86/x64 Internals Deep Dive - Stack Frames, Registers & Memory

## Table of Contents
1. [Register Architecture Comparison](#register-architecture-comparison)
2. [Stack Frame Anatomy](#stack-frame-anatomy)
3. [Memory Layout & Segments](#memory-layout--segments)
4. [Calling Conventions Deep Dive](#calling-conventions-deep-dive)
5. [Security Mitigations](#security-mitigations)
6. [Exception Handling](#exception-handling)
7. [Virtual Memory & Paging](#virtual-memory--paging)
8. [CPU Privilege Levels](#cpu-privilege-levels)
9. [Interrupt & System Call Mechanisms](#interrupt--system-call-mechanisms)

---

## Register Architecture Comparison

### x86 (32-bit) Registers

```
┌─────────────────────────────────────────────────────────┐
│ General Purpose Registers (32-bit)                      │
├─────────────────────────────────────────────────────────┤
│ EAX  │  AX  │ AH │ AL │  Accumulator / Return Value    │
│ EBX  │  BX  │ BH │ BL │  Base Register                 │
│ ECX  │  CX  │ CH │ CL │  Counter Register              │
│ EDX  │  DX  │ DH │ DL │  Data Register                 │
│ ESI  │  SI  │    │    │  Source Index                  │
│ EDI  │  DI  │    │    │  Destination Index             │
│ EBP  │  BP  │    │    │  Base Pointer / Frame Pointer  │
│ ESP  │  SP  │    │    │  Stack Pointer                 │
└─────────────────────────────────────────────────────────┘

Special Registers:
- EIP: Instruction Pointer (cannot be directly accessed)
- EFLAGS: Status and control flags

Segment Registers (16-bit):
- CS: Code Segment
- DS: Data Segment
- SS: Stack Segment
- ES, FS, GS: Extra Segments
```

### x64 (64-bit) Registers

```
┌──────────────────────────────────────────────────────────────┐
│ General Purpose Registers (64-bit)                           │
├──────────────────────────────────────────────────────────────┤
│ RAX │ EAX │  AX  │ AH │ AL │  Accumulator / Return Value   │
│ RBX │ EBX │  BX  │ BH │ BL │  Base Register (callee-saved) │
│ RCX │ ECX │  CX  │ CH │ CL │  Counter / 1st arg (Win)      │
│ RDX │ EDX │  DX  │ DH │ DL │  Data / 2nd arg (Win)         │
│ RSI │ ESI │  SI  │    │SIL │  Source Index / 2nd arg (Lin) │
│ RDI │ EDI │  DI  │    │DIL │  Dest Index / 1st arg (Lin)   │
│ RBP │ EBP │  BP  │    │BPL │  Base Pointer (callee-saved)  │
│ RSP │ ESP │  SP  │    │SPL │  Stack Pointer                │
├──────────────────────────────────────────────────────────────┤
│ R8  │ R8D │ R8W  │    │R8B │  3rd arg (Win) / 5th (Lin)    │
│ R9  │ R9D │ R9W  │    │R9B │  4th arg (Win) / 6th (Lin)    │
│ R10 │R10D │R10W  │    │R10B│  Syscall scratch (Win)        │
│ R11 │R11D │R11W  │    │R11B│  Syscall scratch              │
│ R12 │R12D │R12W  │    │R12B│  General purpose (callee-saved)│
│ R13 │R13D │R13W  │    │R13B│  General purpose (callee-saved)│
│ R14 │R14D │R14W  │    │R14B│  General purpose (callee-saved)│
│ R15 │R15D │R15W  │    │R15B│  General purpose (callee-saved)│
└──────────────────────────────────────────────────────────────┘

Special Registers:
- RIP: Instruction Pointer (64-bit)
- RFLAGS: Extended status and control flags

Segment Registers (mostly legacy in x64):
- FS: Linux TLS, Windows not used in user mode
- GS: Windows TEB/PEB access, Linux kernel data
```

### Register Width Behavior (CRITICAL)

```asm
; x64 Zero-Extension Behavior:
mov eax, 0x12345678     ; RAX = 0x0000000012345678 (upper 32 bits ZEROED!)
mov ax, 0x1234          ; RAX = 0x0000000012341234 (upper 48 bits unchanged)
mov al, 0x12            ; RAX = 0x0000000012341212 (upper 56 bits unchanged)

; This matters for exploitation:
xor eax, eax            ; Zeros entire RAX (mov rax, 0 alternative)
xor ax, ax              ; Only zeros lower 16 bits!
```

**Security Implication:**
- Writing to 32-bit register (EAX) zeros upper 32 bits of 64-bit register (RAX)
- Writing to 16/8-bit registers does NOT zero upper bits
- Can lead to information leaks if upper bits contain sensitive data

---

## Stack Frame Anatomy

### x86 (32-bit) Stack Frame

```
High Addresses
    ↓
┌──────────────────────────┐
│  Argument N              │  [ebp + 4*N + 8]
│  ...                     │
│  Argument 2              │  [ebp + 12]
│  Argument 1              │  [ebp + 8]
│  Return Address          │  [ebp + 4]    ← Exploitation target!
├──────────────────────────┤  ← EBP points here
│  Saved EBP               │  [ebp]
├──────────────────────────┤
│  Local Variable 1        │  [ebp - 4]
│  Local Variable 2        │  [ebp - 8]
│  ...                     │
│  Buffer[0..N]            │  [ebp - offset]
├──────────────────────────┤  ← ESP points here (top of stack)
│  (unused stack space)    │
└──────────────────────────┘
    ↑
Low Addresses
```

**Function Prologue (x86):**
```asm
push ebp                ; Save caller's frame pointer
mov ebp, esp            ; Set up new frame pointer
sub esp, 0x20           ; Allocate 32 bytes for locals
```

**Function Epilogue (x86):**
```asm
mov esp, ebp            ; Restore stack pointer (or: leave)
pop ebp                 ; Restore caller's frame pointer
ret                     ; Return (pop EIP from stack)
```

---

### x64 (64-bit) Stack Frame

```
High Addresses
    ↓
┌──────────────────────────┐
│  Argument 7              │  [rbp + 0x30]
│  Argument 6              │  [rbp + 0x28]
│  Argument 5              │  [rbp + 0x20]
├──────────────────────────┤
│  Shadow Space (0x20)     │  [rbp + 0x10] to [rbp + 0x1f] (Windows only)
├──────────────────────────┤
│  Return Address          │  [rbp + 8]     ← Exploitation target!
├──────────────────────────┤  ← RBP points here
│  Saved RBP               │  [rbp]
├──────────────────────────┤
│  Local Variable 1        │  [rbp - 8]
│  Local Variable 2        │  [rbp - 16]
│  ...                     │
│  Buffer[0..N]            │  [rbp - offset]
├──────────────────────────┤
│  Stack Canary (optional) │  [rbp - canary_offset]
├──────────────────────────┤  ← RSP points here
│  (unused stack space)    │
└──────────────────────────┘
    ↑
Low Addresses
```

**Function Prologue (x64):**
```asm
push rbp                ; Save caller's frame pointer
mov rbp, rsp            ; Set up new frame pointer
sub rsp, 0x30           ; Allocate 48 bytes for locals
                        ; (Must be 16-byte aligned!)
```

**Function Epilogue (x64):**
```asm
leave                   ; mov rsp, rbp; pop rbp
ret                     ; Return (pop RIP from stack)
```

---

### Stack Alignment Requirements

**x86 (32-bit):**
- Stack must be 4-byte aligned before `call`
- Some compilers require 16-byte alignment for SSE instructions

**x64 (64-bit):**
- **CRITICAL**: Stack must be 16-byte aligned before `call`
- RSP must be aligned to 16 bytes when calling functions
- After `call`, RSP is misaligned by 8 (return address pushed)
- Function prologue must adjust to restore alignment

**Example:**
```asm
; Before calling function, RSP must be 16-byte aligned
; RSP = 0x7fffffffe000  (aligned)
call func               ; Pushes return address (8 bytes)
                        ; RSP = 0x7fffffffdff8  (misaligned by 8!)

; Inside func:
push rbp                ; RSP = 0x7fffffffdff0  (aligned again)
mov rbp, rsp
sub rsp, 0x20           ; RSP = 0x7fffffffdfd0  (still aligned)
```

**Exploitation Implication:**
- Stack misalignment can cause crashes even with valid ROP chains
- Must ensure RSP is 16-byte aligned before calling functions

---

## Memory Layout & Segments

### Process Memory Layout (Linux x64)

```
High Addresses (0x7fffffffffff)
    ↓
┌────────────────────────────────┐
│  Kernel Space                  │  0xffff800000000000+
│  (inaccessible from user mode) │
├────────────────────────────────┤
│  Stack (grows downward ↓)      │  0x7fffffffffff
│  - Command line arguments      │
│  - Environment variables       │
│  - Local variables             │
│  - Return addresses            │  ← Exploitation target
├────────────────────────────────┤
│  Memory Mapped Region          │  0x7ffff7000000
│  - Shared libraries (.so)      │
│  - mmap() allocations          │
├────────────────────────────────┤
│  Heap (grows upward ↑)         │  0x555555600000
│  - malloc() / new allocations  │
│  - Use-after-free targets      │
├────────────────────────────────┤
│  BSS (uninitialized data)      │  0x555555558000
│  - Global/static variables     │
│  - Initialized to zero         │
├────────────────────────────────┤
│  Data (initialized data)       │  0x555555557000
│  - Global/static variables     │
│  - Writable constants          │
├────────────────────────────────┤
│  Text (code)                   │  0x555555554000
│  - Executable instructions     │
│  - Read-only (usually)         │
│  - ROP gadgets location        │
└────────────────────────────────┘
    ↑
Low Addresses (0x0000000000000000)
```

### Windows x64 Memory Layout

```
High Addresses (0x7FFFFFFFFFFF)
    ↓
┌────────────────────────────────┐
│  Kernel Space                  │  0xFFFF800000000000+
│  (ntoskrnl.exe, drivers)       │
├────────────────────────────────┤
│  User-mode address space limit │  0x00007FFFFFFFFFFF
├────────────────────────────────┤
│  Stack (Thread Stack)          │  Variable location
│  - TEB at top of stack         │
│  - Stack frames below          │
├────────────────────────────────┤
│  Heap (Default Process Heap)   │  Variable location
│  - Multiple heaps possible     │
│  - LFH (Low Fragmentation Heap)│
├────────────────────────────────┤
│  DLLs (System Libraries)       │  Variable location
│  - ntdll.dll (always present)  │
│  - kernel32.dll, kernelbase.dll│
│  - Other system DLLs           │
├────────────────────────────────┤
│  PEB (Process Environment)     │  Variable location
│  - Process parameters          │
│  - Loaded module list          │
├────────────────────────────────┤
│  Image Base (EXE)              │  Default: 0x140000000
│  - .text section (code)        │
│  - .data section               │
│  - .rdata section (read-only)  │
└────────────────────────────────┘
    ↑
Low Addresses (0x0000000000000000)
```

**Security Notes:**
- ASLR randomizes base addresses of stack, heap, and modules
- NULL page (0x0-0x10000) is unmapped to prevent NULL pointer exploits
- DEP/NX prevents execution from stack/heap

---

## Calling Conventions Deep Dive

### Windows x64 (Microsoft Calling Convention)

**Registers:**
```
Arguments:     RCX, RDX, R8, R9, [stack+0x20], [stack+0x28], ...
FP Arguments:  XMM0, XMM1, XMM2, XMM3
Return Value:  RAX (integer), XMM0 (floating point)
Caller-saved:  RAX, RCX, RDX, R8, R9, R10, R11
Callee-saved:  RBX, RBP, RDI, RSI, RSP, R12-R15
```

**Shadow Space (CRITICAL for Windows):**
```asm
; Caller must allocate 32 bytes (0x20) of "shadow space" for first 4 args
; Even if function takes fewer than 4 args!

sub rsp, 0x28               ; Shadow space (0x20) + alignment (0x8)
mov rcx, arg1               ; 1st argument
mov rdx, arg2               ; 2nd argument
mov r8, arg3                ; 3rd argument
mov r9, arg4                ; 4th argument
mov qword [rsp+0x20], arg5  ; 5th argument (on stack after shadow space)
call function
add rsp, 0x28               ; Clean up
```

**Detailed Stack Layout:**
```
Before call:
RSP → [aligned to 16 bytes]

After call instruction:
RSP → Return address        [rsp]

After prologue (push rbp; mov rbp, rsp; sub rsp, 0x30):
      Shadow space arg4     [rbp + 0x38]
      Shadow space arg3     [rbp + 0x30]
      Shadow space arg2     [rbp + 0x28]
      Shadow space arg1     [rbp + 0x20]
      Return address        [rbp + 8]
RBP → Saved RBP             [rbp]
      Local variables       [rbp - ...]
RSP → Top of stack          (rbp - 0x30)
```

---

### Linux/macOS x64 (System V AMD64 ABI)

**Registers:**
```
Arguments:     RDI, RSI, RDX, RCX, R8, R9, [stack], [stack+8], ...
FP Arguments:  XMM0-XMM7
Return Value:  RAX (integer), RDX:RAX (128-bit), XMM0 (FP)
Caller-saved:  RAX, RCX, RDX, RSI, RDI, R8-R11
Callee-saved:  RBX, RBP, RSP, R12-R15
```

**No Shadow Space:**
```asm
; No shadow space required on Linux/macOS
mov rdi, arg1               ; 1st argument
mov rsi, arg2               ; 2nd argument
mov rdx, arg3               ; 3rd argument
mov rcx, arg4               ; 4th argument
mov r8, arg5                ; 5th argument
mov r9, arg6                ; 6th argument
push arg8                   ; 8th argument (stack grows down)
push arg7                   ; 7th argument
call function
add rsp, 0x10               ; Clean up stack args (2 * 8 bytes)
```

**Detailed Stack Layout:**
```
Before call:
RSP → [aligned to 16 bytes]

After call instruction:
RSP → Return address        [rsp]

After prologue (push rbp; mov rbp, rsp; sub rsp, 0x20):
      Stack argument 2      [rbp + 0x18]
      Stack argument 1      [rbp + 0x10]
      Return address        [rbp + 8]
RBP → Saved RBP             [rbp]
      Local variables       [rbp - ...]
RSP → Top of stack          (rbp - 0x20)
```

---

### Calling Convention Comparison Table

| Feature           | Windows x64      | Linux/macOS x64 | x86 (cdecl)    |
|-------------------|------------------|-----------------|----------------|
| 1st int arg       | RCX              | RDI             | [esp+4]        |
| 2nd int arg       | RDX              | RSI             | [esp+8]        |
| 3rd int arg       | R8               | RDX             | [esp+12]       |
| 4th int arg       | R9               | RCX             | [esp+16]       |
| 5th int arg       | [rsp+0x20]       | R8              | [esp+20]       |
| 6th int arg       | [rsp+0x28]       | R9              | [esp+24]       |
| Shadow space      | 32 bytes (0x20)  | None            | None           |
| Stack alignment   | 16 bytes         | 16 bytes        | 4 bytes        |
| Return value      | RAX              | RAX             | EAX            |
| Stack cleanup     | Caller           | Caller          | Caller (cdecl) |
| Callee-saved regs | RBX,RBP,RDI,RSI,R12-R15 | RBX,RBP,R12-R15 | EBX,ESI,EDI,EBP |

---

## Security Mitigations

### Stack Canaries (Stack Cookies)

**Concept:** Place a random value between local variables and return address

**Implementation (Linux GCC):**
```asm
; Function prologue with canary
push rbp
mov rbp, rsp
sub rsp, 0x30
mov rax, fs:[0x28]          ; Load canary from TLS
mov [rbp-0x8], rax          ; Store on stack
xor eax, eax                ; Zero RAX

; ... function body ...

; Function epilogue with canary check
mov rax, [rbp-0x8]          ; Load stored canary
xor rax, fs:[0x28]          ; Compare with original
je .canary_ok               ; Jump if equal
call __stack_chk_fail       ; Abort if mismatch
.canary_ok:
leave
ret
```

**Windows Implementation:**
```asm
; Windows uses __security_cookie global variable
mov rax, qword [__security_cookie]
mov [rbp-0x8], rax

; Later check:
mov rax, [rbp-0x8]
xor rax, qword [__security_cookie]
call __security_check_cookie
```

**Bypass Techniques:**
- Leak the canary value (format string, info leak)
- Overwrite without touching canary (adjacent buffer)
- Brute force (only on forking servers where canary stays same)

---

### ASLR (Address Space Layout Randomization)

**Randomized Components:**
- Stack base address
- Heap base address
- Shared library locations
- Executable base (PIE - Position Independent Executable)

**Example Addresses (same binary, different runs):**
```
Run 1:
Stack:  0x7ffc8b3c0000
Heap:   0x5622ab6c0000
libc:   0x7f3d42e00000

Run 2:
Stack:  0x7ffe12340000  (different!)
Heap:   0x55d0c8a00000  (different!)
libc:   0x7f8c93400000  (different!)
```

**ASLR Entropy (Linux x64):**
- Stack: 30 bits (~1 billion possibilities)
- Heap: 28 bits
- Libraries: 28 bits
- PIE executable: 28 bits

**Bypass Techniques:**
- Information leaks (leak a pointer, calculate offset)
- Partial overwrites (overwrite least significant bytes only)
- Brute force (limited on 32-bit systems)

---

### DEP/NX (Data Execution Prevention / No Execute)

**Concept:** Mark memory pages as either writable OR executable, not both

**Page Permissions:**
```
.text section:   Read + Execute (R-X)
.data section:   Read + Write   (RW-)
.rodata section: Read only      (R--)
Stack:           Read + Write   (RW-)  ← Cannot execute shellcode!
Heap:            Read + Write   (RW-)  ← Cannot execute shellcode!
```

**Bypass Technique: ROP (Return-Oriented Programming)**
```asm
; Instead of executing shellcode on stack, chain existing code fragments:

; ROP chain on stack:
[gadget1]   ; pop rdi; ret
[arg1]      ; Argument for gadget1
[gadget2]   ; pop rsi; ret
[arg2]      ; Argument for gadget2
[system]    ; Address of system()

; Each gadget ends with 'ret' which pops next address from stack
```

---

### CFG/CET (Control Flow Guard / Control-flow Enforcement Technology)

**CFG (Windows):**
- Validates indirect call targets
- Maintains bitmap of valid call targets
- Checks before executing indirect calls

```asm
; Without CFG:
call [rax]                      ; Jump anywhere

; With CFG:
call [__guard_check_icall_fptr] ; Validate RAX first
call [rax]                      ; Only if validation passed
```

**CET (Intel Hardware):**
- **Shadow Stack**: Parallel stack for return addresses
- **Indirect Branch Tracking**: Validates indirect jumps

---

## Exception Handling

### SEH (Structured Exception Handling) - Windows x86

**SEH Chain on Stack:**
```
Stack Layout:
┌─────────────────────┐
│  Next SEH Record    │ ← Pointer to next exception handler
├─────────────────────┤
│  Exception Handler  │ ← Address of handler function
├─────────────────────┤
│  ... local vars ... │
└─────────────────────┘
```

**SEH Chain Traversal:**
```
FS:[0] → SEH Record 1 → SEH Record 2 → SEH Record N → 0xFFFFFFFF
```

**Exploitation (Classic SEH Overwrite):**
```asm
; Overflow to overwrite SEH record:
Buffer:    [AAAA...]
SEH Next:  [pointer to shellcode]
SEH Handler: [pop pop ret gadget]

; When exception occurs:
; 1. pop pop ret adjusts stack
; 2. Returns to shellcode in SEH Next field
```

**Modern Protection: SafeSEH**
- Validates handler is in known safe list
- Prevents arbitrary exception handlers

---

### Exception Handling (Linux/Windows x64)

**Table-Based Exception Handling:**
- No SEH chain on stack (x64)
- Exception information in `.pdata` section
- UNWIND_INFO structures describe stack unwinding

**Exploitation Impact:**
- Cannot overwrite SEH chain (doesn't exist on x64)
- Must use other techniques (ROP, vtable hijacking)

---

## Virtual Memory & Paging

### Page Tables (x64)

**4-Level Paging (x64):**
```
Virtual Address (48-bit usable):
┌─────────┬─────────┬─────────┬─────────┬──────────────┐
│  PML4   │   PDP   │   PD    │   PT    │    Offset    │
│ 9 bits  │ 9 bits  │ 9 bits  │ 9 bits  │   12 bits    │
└─────────┴─────────┴─────────┴─────────┴──────────────┘
```

**Page Size:**
- Standard page: 4 KB (0x1000 bytes)
- Large page: 2 MB
- Huge page: 1 GB

**Page Table Entry (PTE) Flags:**
```
Bit 0:  Present (P)         - Page is in memory
Bit 1:  Read/Write (R/W)    - Write permission
Bit 2:  User/Supervisor     - User-mode access allowed
Bit 3:  Write-Through       - Cache policy
Bit 4:  Cache Disable       - Disable caching
Bit 5:  Accessed (A)        - Page was accessed
Bit 6:  Dirty (D)           - Page was written to
Bit 63: Execute Disable(NX) - DEP/NX bit
```

**Security Implications:**
- NX bit (bit 63) prevents code execution
- User/Supervisor bit controls kernel/user access
- Page table exploits can bypass DEP

---

### TLB (Translation Lookaside Buffer)

**Concept:** Cache for virtual-to-physical address translations

**TLB Flushing:**
```asm
mov cr3, rax                ; Reload CR3 flushes TLB
invlpg [address]            ; Invalidate specific page
```

**Exploitation Context:**
- TLB timing attacks (side-channel)
- Spectre/Meltdown exploited TLB behavior

---

## CPU Privilege Levels (Ring Levels)

### x86 Protection Rings

```
┌──────────────────────────────────┐
│  Ring 0 (Kernel Mode)            │  Most privileged
│  - OS kernel                     │  - Full hardware access
│  - Device drivers                │  - Execute privileged instructions
├──────────────────────────────────┤
│  Ring 1 (Rarely used)            │
│  Ring 2 (Rarely used)            │
├──────────────────────────────────┤
│  Ring 3 (User Mode)              │  Least privileged
│  - User applications             │  - Limited hardware access
│  - Normal programs               │  - Cannot execute privileged instr.
└──────────────────────────────────┘
```

**Current Privilege Level (CPL):**
- Stored in CS register (bits 0-1)
- Checked on every memory access and instruction execution

**Privilege Escalation:**
- Kernel exploits transition from Ring 3 → Ring 0
- Goal: Execute kernel code with Ring 0 privileges

---

### Privileged Instructions (Ring 0 Only)

```asm
; These instructions cause #GP fault in Ring 3:
mov cr0, rax                ; Control registers
mov cr3, rax                ; Page table base
lgdt [gdt]                  ; Load GDT
lidt [idt]                  ; Load IDT
hlt                         ; Halt processor
in al, dx                   ; I/O port input (without IOPL)
out dx, al                  ; I/O port output
```

---

## Interrupt & System Call Mechanisms

### Interrupts (x86/x64)

**Interrupt Descriptor Table (IDT):**
```
IDT Entry Structure:
┌─────────────────────────────────┐
│  Offset (low 16 bits)           │
│  Segment Selector               │
│  IST (Interrupt Stack Table)    │  x64 only
│  Type and Attributes            │
│  Offset (middle/high bits)      │
└─────────────────────────────────┘
```

**Common Interrupts:**
```
INT 0x00: Divide by Zero
INT 0x01: Debug Exception
INT 0x03: Breakpoint (0xCC opcode)
INT 0x0D: General Protection Fault
INT 0x0E: Page Fault
INT 0x80: Linux x86 System Call (legacy)
INT 0x2E: Windows x86 System Call (legacy)
```

---

### System Calls

**Linux x86 (Legacy):**
```asm
mov eax, syscall_number     ; e.g., 1 = sys_exit
mov ebx, arg1
mov ecx, arg2
mov edx, arg3
int 0x80                    ; Trigger interrupt
```

**Linux x64 (Modern):**
```asm
mov rax, syscall_number     ; e.g., 60 = sys_exit
mov rdi, arg1
mov rsi, arg2
mov rdx, arg3
mov r10, arg4               ; NOT RCX!
mov r8, arg5
mov r9, arg6
syscall                     ; Fast system call
```

**Windows x64 (Direct Syscall):**
```asm
mov r10, rcx                ; Save RCX
mov eax, syscall_number     ; e.g., 0x55 = NtCreateFile
syscall                     ; Enter kernel
```

**Exploitation Application:**
- Direct syscalls bypass user-mode hooks (EDR evasion)
- Syscall numbers change between Windows versions

---

### SYSENTER/SYSEXIT (x86 Fast System Call)

**Faster than INT (no IDT lookup):**
```asm
; Setup (done by OS):
wrmsr                       ; Write MSR registers (IA32_SYSENTER_*)

; User mode:
mov eax, syscall_number
sysenter                    ; Enter kernel mode

; Kernel mode:
; ... handle syscall ...
sysexit                     ; Return to user mode
```

---

### SYSCALL/SYSRET (x64 Fast System Call)

**Mechanism:**
```asm
; User mode (Ring 3):
syscall                     ; RIP saved to RCX, RFLAGS to R11
                            ; Jump to MSR IA32_LSTAR address

; Kernel mode (Ring 0):
; ... handle syscall ...
; RAX contains return value

sysret                      ; RIP restored from RCX, RFLAGS from R11
```

**Important Registers:**
- **RCX**: Saved RIP (return address)
- **R11**: Saved RFLAGS
- **RAX**: Return value

**Security Note:**
- Kernel must sanitize user input from registers
- Incorrect validation = kernel exploitation

---

## Advanced Topics for Exploitation

### SMEP/SMAP (Kernel Protections)

**SMEP (Supervisor Mode Execution Prevention):**
- Prevents kernel from executing user-mode pages
- Stops classic "jump to user shellcode" attacks

**SMAP (Supervisor Mode Access Prevention):**
- Prevents kernel from accessing user-mode pages
- Stops kernel from dereferencing user pointers

**Bypass Techniques:**
- ROP in kernel space
- Disable SMEP by modifying CR4 register
- ret2usr with SMEP bypass

---

### Kernel Stack vs User Stack

**Separate Stacks:**
```
User Mode (Ring 3):
RSP → User Stack              [e.g., 0x7fff...]

System Call / Interrupt:
[Stack switch occurs]

Kernel Mode (Ring 0):
RSP → Kernel Stack            [e.g., 0xffff...]
```

**Stack Switch Mechanism:**
- On syscall/interrupt, CPU loads kernel stack from TSS (Task State Segment)
- Kernel stack is per-thread
- User context saved on kernel stack

---

### Context Switching

**Saved Context (on interrupt/syscall):**
```
Kernel Stack after interrupt:
┌──────────────────┐
│  User SS         │  Stack segment
│  User RSP        │  User stack pointer
│  User RFLAGS     │  Flags
│  User CS         │  Code segment
│  User RIP        │  Instruction pointer
├──────────────────┤
│  Error Code      │  (for some interrupts)
├──────────────────┤
│  Saved registers │  RAX, RBX, RCX, etc.
└──────────────────┘
```

---

## Memory Forensics & Debugging

### Key Structures to Know

**PEB (Process Environment Block) - Windows:**
```
Offset  Field
0x000   InheritedAddressSpace
0x002   ReadImageFileExecOptions
0x003   BeingDebugged              ← Anti-debug check
0x008   Mutant
0x010   ImageBaseAddress           ← EXE base address
0x018   Ldr                        ← Pointer to PEB_LDR_DATA
0x020   ProcessParameters
0x060   ProcessHeap                ← Default heap
```

**TEB (Thread Environment Block) - Windows:**
```
Offset  Field
0x000   NT_TIB (Thread Information Block)
0x000   ExceptionList              ← SEH chain (x86 only)
0x018   Self                       ← Pointer to TEB itself
0x020   ProcessEnvironmentBlock    ← Pointer to PEB
0x028   StackBase                  ← Top of stack
0x030   StackLimit                 ← Bottom of stack
0x060   TlsSlots[64]              ← Thread-local storage
```

**Access from Assembly:**
```asm
; Windows x64:
mov rax, gs:[0x30]          ; TEB
mov rax, gs:[0x60]          ; PEB

; Linux x64:
mov rax, fs:[0x00]          ; TLS base
mov rax, fs:[0x28]          ; Stack canary
```

---

## Checklist for Exploitation

### Stack-Based Buffer Overflow
- [ ] Calculate offset to return address
- [ ] Check for stack canaries (look for `fs:[0x28]` or `__security_cookie`)
- [ ] Verify stack alignment (16-byte on x64)
- [ ] Build ROP chain if DEP/NX enabled
- [ ] Leak addresses if ASLR enabled

### Heap Exploitation
- [ ] Identify heap allocator (glibc, Windows LFH, etc.)
- [ ] Understand chunk metadata structure
- [ ] Check for heap cookies/guards
- [ ] Find use-after-free or double-free vulnerabilities
- [ ] Craft heap layout for exploitation (heap feng shui)

### Kernel Exploitation
- [ ] Identify kernel version and mitigations
- [ ] Check for SMEP/SMAP
- [ ] Find arbitrary read/write primitive
- [ ] Locate kernel structures (e.g., cred struct on Linux)
- [ ] Plan privilege escalation (token stealing on Windows)

### ROP Chain Building
- [ ] Find gadgets in executable code sections
- [ ] Ensure gadgets don't break on NULL bytes (if needed)
- [ ] Verify stack alignment
- [ ] Chain gadgets to set up function arguments
- [ ] Call target function (system(), WinExec(), etc.)

---

## Summary: What You MUST Know

### For Stack Exploitation:
1. **Stack frame layout** (where locals, saved registers, return address are)
2. **Calling conventions** (Windows vs Linux argument passing)
3. **Stack alignment** (16-byte on x64)
4. **How `call`/`ret` work** (push/pop RIP)

### For Understanding Code:
1. **Register purposes** (RAX=return, RDI/RCX=1st arg, etc.)
2. **Memory access patterns** (`mov rax, [rbx]` vs `lea rax, [rbx]`)
3. **Control flow** (conditional jumps, function calls)

### For Bypassing Mitigations:
1. **Stack canaries** (random value before return address)
2. **ASLR** (randomized addresses)
3. **DEP/NX** (non-executable stack/heap)
4. **CFG/CET** (control flow validation)

### For Advanced Exploitation:
1. **Privilege levels** (Ring 0 vs Ring 3)
2. **System calls** (how to transition to kernel)
3. **Exception handling** (SEH on x86, table-based on x64)
4. **Virtual memory** (page tables, permissions)

---

*This guide covers the essential internals needed for vulnerability research and exploitation on x86/x64 platforms.*
