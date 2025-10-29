# x86/x86_64 Assembly Reference Guide

## Table of Contents
1. [General Purpose Registers](#general-purpose-registers)
2. [Special Purpose Registers](#special-purpose-registers)
3. [Segment Registers](#segment-registers)
4. [Common Instructions](#common-instructions)
5. [Control Flow Instructions](#control-flow-instructions)
6. [Stack Operations](#stack-operations)
7. [Arithmetic & Logic](#arithmetic--logic)
8. [Memory Access](#memory-access)
9. [String Operations](#string-operations)
10. [System & Special](#system--special)

---

## General Purpose Registers

### RAX / EAX / AX / AL
**Accumulator / Return Value Register**
- `RAX`: Full 64-bit (0x0000000000000000 - 0xFFFFFFFFFFFFFFFF)
- `EAX`: Lower 32-bit (0x00000000 - 0xFFFFFFFF)
- `AX`: Lower 16-bit (0x0000 - 0xFFFF)
- `AL`: Lowest 8-bit (0x00 - 0xFF)
- `AH`: High 8-bit of AX (rarely used in x64)

**Primary Use:**
- Function return values
- Fast arithmetic operations
- Accumulator for multiply/divide

**Example:**
```asm
mov rax, 5          ; RAX = 5
add rax, 10         ; RAX = 15
xor eax, eax        ; Clear EAX (also zeros upper 32 bits of RAX)
```

---

### RBX / EBX / BX / BL
**General Purpose / Base Register**
- `RBX`: Full 64-bit
- `EBX`: Lower 32-bit
- `BX`: Lower 16-bit
- `BL`: Lowest 8-bit

**Primary Use:**
- General-purpose storage
- **Callee-saved** on x64 (function must preserve it)
- Often used as base pointer for memory addressing

**Calling Convention:**
- **Must be preserved** across function calls (push/pop or save/restore)

**Example:**
```asm
mov rbx, [rdi]      ; Load value from memory
add rbx, 0x100      ; Offset calculation
mov rax, [rbx]      ; Use as base pointer
```

---

### RCX / ECX / CX / CL
**Counter Register / 1st Argument (Windows)**
- `RCX`: Full 64-bit
- `ECX`: Lower 32-bit
- `CX`: Lower 16-bit
- `CL`: Lowest 8-bit

**Primary Use:**
- **1st function argument on Windows x64**
- Loop counter (with `loop` instruction)
- Shift/rotate count (CL register)
- String operation counter

**Calling Convention:**
- **Windows x64**: 1st integer/pointer argument
- **Linux/macOS x64**: 4th argument
- **Caller-saved** (not preserved across calls)

**Example:**
```asm
; Windows x64 function call
mov rcx, pFilename      ; 1st arg
call CreateFileA

; Loop counter
mov rcx, 10
loop_start:
    ; ... code ...
    loop loop_start     ; Decrements RCX, jumps if not zero

; Shift operations
mov cl, 4
shl rax, cl             ; Shift RAX left by 4 bits
```

---

### RDX / EDX / DX / DL
**Data Register / 2nd Argument (Windows)**
- `RDX`: Full 64-bit
- `EDX`: Lower 32-bit
- `DX`: Lower 16-bit
- `DL`: Lowest 8-bit

**Primary Use:**
- **2nd function argument on Windows x64**
- High part of multiply/divide operations
- I/O port operations

**Calling Convention:**
- **Windows x64**: 2nd integer/pointer argument
- **Linux/macOS x64**: 3rd argument
- **Caller-saved**

**Example:**
```asm
; Windows x64
mov rdx, dwDesiredAccess    ; 2nd arg
call CreateFileA

; Multiply (result in RDX:RAX)
mov rax, 0x100000000
mov rbx, 2
mul rbx                     ; RDX:RAX = RAX * RBX
```

---

### RSI / ESI / SI / SIL
**Source Index Register / 2nd Argument (Linux)**
- `RSI`: Full 64-bit
- `ESI`: Lower 32-bit
- `SI`: Lower 16-bit
- `SIL`: Lowest 8-bit

**Primary Use:**
- **2nd function argument on Linux/macOS x64**
- Source pointer for string operations
- General-purpose register

**Calling Convention:**
- **Linux/macOS x64**: 2nd integer/pointer argument
- **Caller-saved**

**Example:**
```asm
; Linux x64 function call
mov rsi, source_buffer      ; 2nd arg (source)
call memcpy

; String operation
lea rsi, [source]
lea rdi, [dest]
rep movsb                   ; Copy from RSI to RDI
```

---

### RDI / EDI / DI / DIL
**Destination Index Register / 1st Argument (Linux)**
- `RDI`: Full 64-bit
- `EDI`: Lower 32-bit
- `DI`: Lower 16-bit
- `DIL`: Lowest 8-bit

**Primary Use:**
- **1st function argument on Linux/macOS x64**
- Destination pointer for string operations
- General-purpose register

**Calling Convention:**
- **Linux/macOS x64**: 1st integer/pointer argument
- **Caller-saved**

**Example:**
```asm
; Linux x64 function call
mov rdi, dest_buffer        ; 1st arg (destination)
call strcpy

; String operation
lea rdi, [buffer]
mov al, 0
mov rcx, 100
rep stosb                   ; Fill RDI with AL (zero buffer)
```

---

### RBP / EBP / BP / BPL
**Base Pointer / Frame Pointer**
- `RBP`: Full 64-bit
- `EBP`: Lower 32-bit
- `BP`: Lower 16-bit
- `BPL`: Lowest 8-bit

**Primary Use:**
- Stack frame base pointer
- Reference local variables and function parameters
- **Callee-saved** (must be preserved)

**Common Pattern:**
```asm
; Function prologue
push rbp                ; Save old frame pointer
mov rbp, rsp            ; Set up new frame
sub rsp, 0x20           ; Allocate local variables

; Access locals
mov [rbp-0x10], rax     ; Store to local variable
mov rax, [rbp+0x10]     ; Access function parameter

; Function epilogue
mov rsp, rbp            ; (or: leave instruction)
pop rbp
ret
```

**Security Note:**
- Local variables at `[rbp - offset]`
- Saved RBP at `[rbp]`
- Return address at `[rbp + 8]` on x64

---

### RSP / ESP / SP / SPL
**Stack Pointer**
- `RSP`: Full 64-bit
- `ESP`: Lower 32-bit
- `SP`: Lower 16-bit
- `SPL`: Lowest 8-bit

**Primary Use:**
- Points to top of stack
- Automatically updated by `push`/`pop`/`call`/`ret`
- **CRITICAL**: Stack grows DOWN (toward lower addresses)

**Important Operations:**
```asm
push rax                ; RSP -= 8, [RSP] = RAX
pop rax                 ; RAX = [RSP], RSP += 8
call func               ; push RIP, jump to func
ret                     ; pop RIP

; Manual stack manipulation
sub rsp, 0x20           ; Allocate 32 bytes
add rsp, 0x20           ; Deallocate 32 bytes

; Stack pivot (exploitation)
mov rsp, rax            ; Set stack to arbitrary location
xchg rsp, rax           ; Swap stack with RAX
```

**Security Insight:**
- Buffer overflows overwrite toward higher addresses (toward return address)
- Stack canaries placed just before return address

---

### R8 - R15 (x64 Only)
**Extended General Purpose Registers**

#### R8 / R8D / R8W / R8B
**3rd Argument (Windows)**
- **Windows x64**: 3rd integer/pointer argument
- **Linux/macOS x64**: 5th argument
- **Caller-saved**

```asm
mov r8, dwShareMode         ; Windows: 3rd arg
call CreateFileA
```

---

#### R9 / R9D / R9W / R9B
**4th Argument (Windows)**
- **Windows x64**: 4th integer/pointer argument
- **Linux/macOS x64**: 6th argument
- **Caller-saved**

```asm
mov r9, lpSecurityAttributes    ; Windows: 4th arg
call CreateFileA
```

---

#### R10 / R10D / R10W / R10B
**General Purpose / Syscall (Windows)**
- Used in Windows syscall convention (`mov r10, rcx`)
- **Caller-saved**

```asm
; Windows syscall
mov r10, rcx                ; Save RCX to R10
mov eax, syscall_number     ; System call number
syscall                     ; Execute syscall
```

---

#### R11 / R11D / R11W / R11B
**General Purpose / Syscall Scratch**
- Destroyed by syscall/sysret
- **Caller-saved**

---

#### R12 - R15
**General Purpose**
- **Callee-saved** (must be preserved)
- Often used for persistent values across function calls

```asm
; Function must preserve these
push r12
push r13
mov r12, [rdi]              ; Use as temp storage
mov r13, [rsi]
; ... function body ...
pop r13
pop r12
ret
```

---

## Special Purpose Registers

### RIP / EIP / IP
**Instruction Pointer**
- Points to the **next instruction** to execute
- Cannot be directly modified (use jumps/calls)
- Modified by: `jmp`, `call`, `ret`, `jcc` (conditional jumps)

**RIP-Relative Addressing (x64):**
```asm
lea rax, [rip + 0x100]      ; Load address relative to RIP
mov rax, [rip + offset]     ; Access data relative to RIP
```

**Security Insight:**
- Return address on stack is the value that goes into RIP
- Controlling return address = controlling RIP = code execution

---

### RFLAGS / EFLAGS / FLAGS
**Status and Control Flags**

#### Important Flags:

**CF (Carry Flag) - Bit 0**
- Set if unsigned arithmetic overflow/underflow
```asm
mov al, 0xFF
add al, 1               ; CF=1 (carry out of highest bit)
```

**PF (Parity Flag) - Bit 2**
- Set if result has even number of 1 bits

**ZF (Zero Flag) - Bit 6**
- Set if result is zero
```asm
test rax, rax           ; Set ZF if RAX = 0
jz is_zero              ; Jump if ZF = 1
```

**SF (Sign Flag) - Bit 7**
- Set if result is negative (MSB = 1)
```asm
cmp rax, 10             ; Compare RAX with 10
js negative             ; Jump if SF = 1
```

**OF (Overflow Flag) - Bit 11**
- Set if signed arithmetic overflow
```asm
mov al, 127
add al, 1               ; OF=1 (signed overflow)
jo overflow_handler
```

**DF (Direction Flag) - Bit 10**
- Controls string operation direction
```asm
cld                     ; Clear DF (forward direction)
std                     ; Set DF (backward direction)
rep movsb               ; Copy using direction from DF
```

---

## Segment Registers

### FS (x64 Linux/Windows User Mode)
**Linux**: Thread-Local Storage (TLS)
**Windows**: Not typically used in user mode

```asm
; Linux: Access TLS
mov rax, fs:[0x28]          ; Stack canary location
```

### GS (x64 Windows User Mode)
**Windows**: Thread Environment Block (TEB) / Process Environment Block (PEB)

```asm
; Windows x64
mov rax, gs:[0x30]          ; TEB pointer
mov rax, gs:[0x60]          ; PEB pointer
```

**Security Applications:**
```asm
; Get PEB (Process Environment Block)
mov rax, gs:[0x60]

; Get TEB (Thread Environment Block)
mov rax, gs:[0x30]

; Common exploitation pattern
mov rax, gs:[0x60]          ; PEB
mov rax, [rax + 0x18]       ; PEB.Ldr
; ... walk linked list for module base addresses
```

---

## Common Instructions

### MOV - Move Data
```asm
mov dest, src               ; dest = src

; Examples
mov rax, 0x1234             ; Immediate to register
mov rax, rbx                ; Register to register
mov rax, [rbx]              ; Memory to register (dereference)
mov [rax], rbx              ; Register to memory
mov rax, [rbx + rcx*8]      ; Array access
```

**Width Variants:**
```asm
mov al, [rbx]               ; Move 1 byte
mov ax, [rbx]               ; Move 2 bytes
mov eax, [rbx]              ; Move 4 bytes (zeros upper 32 bits)
mov rax, [rbx]              ; Move 8 bytes
```

---

### LEA - Load Effective Address
**Does NOT dereference - just calculates address**
```asm
lea rax, [rbx + rcx*8 + 0x10]   ; RAX = RBX + RCX*8 + 0x10

; Common uses
lea rdi, [rsi + 0x100]          ; Calculate offset address
lea rax, [rax + rax*4]          ; RAX = RAX * 5 (fast multiply)
lea rsp, [rsp - 0x20]           ; Adjust stack (alternative to sub)
```

**vs MOV:**
```asm
mov rax, [rbx + 0x10]           ; RAX = *(RBX + 0x10) - dereference!
lea rax, [rbx + 0x10]           ; RAX = RBX + 0x10 - just the address
```

---

### PUSH / POP - Stack Operations
```asm
push rax                    ; RSP -= 8, [RSP] = RAX
pop rax                     ; RAX = [RSP], RSP += 8

push 0x41414141             ; Push immediate value
pushfq                      ; Push RFLAGS
popfq                       ; Pop RFLAGS
```

**Security Pattern:**
```asm
; Typical function entry
push rbp
push rbx
push r12                    ; Preserve callee-saved registers
```

---

### CALL / RET - Function Calls
```asm
call function               ; push RIP, jmp function
ret                         ; pop RIP
ret 0x10                    ; pop RIP, add 0x10 to RSP (cleanup args)

; Direct call
call 0x401000

; Indirect call (exploitation target!)
call rax                    ; Jump to address in RAX
call [rax]                  ; Jump to address stored at [RAX]
call [rax + 0x10]          ; Virtual function call pattern
```

**Security Insight:**
- `call [rax + offset]` = virtual function call
- If you control RAX, you control execution

---

## Control Flow Instructions

### Unconditional Jumps
```asm
jmp label                   ; Jump to label
jmp rax                     ; Jump to address in RAX (indirect)
jmp [rax]                   ; Jump to address at [RAX]
```

---

### Conditional Jumps

**Zero Flag:**
```asm
je / jz     label           ; Jump if Equal / Zero (ZF=1)
jne / jnz   label           ; Jump if Not Equal / Not Zero (ZF=0)
```

**Signed Comparisons:**
```asm
jg  label                   ; Jump if Greater (SF=OF, ZF=0)
jge label                   ; Jump if Greater or Equal (SF=OF)
jl  label                   ; Jump if Less (SF≠OF)
jle label                   ; Jump if Less or Equal (SF≠OF or ZF=1)
```

**Unsigned Comparisons:**
```asm
ja  label                   ; Jump if Above (CF=0, ZF=0)
jae label                   ; Jump if Above or Equal (CF=0)
jb  label                   ; Jump if Below (CF=1)
jbe label                   ; Jump if Below or Equal (CF=1 or ZF=1)
```

**Other Conditions:**
```asm
js  label                   ; Jump if Sign (SF=1, negative)
jns label                   ; Jump if Not Sign (SF=0, positive)
jo  label                   ; Jump if Overflow (OF=1)
jno label                   ; Jump if Not Overflow (OF=0)
```

**Common Pattern:**
```asm
cmp rax, 0x1000             ; Compare RAX with 0x1000
ja  too_large               ; Jump if RAX > 0x1000 (unsigned)

test rax, rax               ; Check if RAX is zero
jz is_null                  ; Jump if RAX = 0
```

---

### CMP / TEST - Comparisons
```asm
cmp op1, op2                ; Sets flags based on (op1 - op2)
test op1, op2               ; Sets flags based on (op1 & op2)
```

**Examples:**
```asm
; Check if RAX >= 0x100
cmp rax, 0x100
jae greater_or_equal

; Check if pointer is NULL
test rax, rax               ; Faster than cmp rax, 0
jz is_null

; Check if bit is set
test rax, 0x80000000
jnz bit_is_set
```

---

## Arithmetic & Logic

### ADD / SUB
```asm
add dest, src               ; dest = dest + src
sub dest, src               ; dest = dest - src

add rax, 10
sub rax, rbx
add rax, [rbx]              ; Add value from memory
```

---

### INC / DEC
```asm
inc rax                     ; RAX++
dec rax                     ; RAX--

; Loop pattern
mov rcx, 10
loop_start:
    ; ... code ...
    dec rcx
    jnz loop_start
```

---

### MUL / IMUL - Multiply
```asm
; Unsigned multiply
mul rbx                     ; RDX:RAX = RAX * RBX

; Signed multiply (3 forms)
imul rbx                    ; RDX:RAX = RAX * RBX
imul rax, rbx               ; RAX = RAX * RBX
imul rax, rbx, 10           ; RAX = RBX * 10
```

---

### DIV / IDIV - Divide
```asm
; Unsigned divide
xor rdx, rdx                ; Clear RDX (high part)
mov rax, 100                ; Dividend
mov rbx, 3                  ; Divisor
div rbx                     ; RAX = quotient, RDX = remainder

; Signed divide
cqo                         ; Sign-extend RAX into RDX
idiv rbx
```

---

### Bitwise Operations
```asm
and rax, rbx                ; RAX &= RBX
or  rax, rbx                ; RAX |= RBX
xor rax, rbx                ; RAX ^= RBX
not rax                     ; RAX = ~RAX

; Common patterns
xor rax, rax                ; Zero RAX (faster than mov rax, 0)
or rax, rax                 ; Test if RAX is zero (sets ZF)
and rax, 0xFFFFFFF0         ; Align to 16-byte boundary
```

---

### Shift Operations
```asm
shl rax, count              ; Logical shift left
shr rax, count              ; Logical shift right
sal rax, count              ; Arithmetic shift left (same as shl)
sar rax, count              ; Arithmetic shift right (sign-extend)

; Examples
shl rax, 3                  ; Multiply by 8
shr rax, 2                  ; Divide by 4 (unsigned)
shl rax, cl                 ; Shift by CL register
```

---

### Rotate Operations
```asm
rol rax, count              ; Rotate left
ror rax, count              ; Rotate right
rcl rax, count              ; Rotate left through carry
rcr rax, count              ; Rotate right through carry
```

---

## Memory Access

### MOVSX / MOVZX - Sign/Zero Extend
```asm
movsx rax, byte [rbx]       ; Sign-extend byte to 64-bit
movzx rax, byte [rbx]       ; Zero-extend byte to 64-bit

movsx rax, word [rbx]       ; Sign-extend 16-bit to 64-bit
movzx eax, word [rbx]       ; Zero-extend 16-bit to 32-bit
```

---

### XCHG - Exchange
```asm
xchg rax, rbx               ; Swap RAX and RBX

; Exploitation pattern
xchg rsp, rax               ; Stack pivot!
```

---

### CMOV - Conditional Move (Avoiding Branches)
```asm
cmove  rax, rbx             ; Move if equal (ZF=1)
cmovne rax, rbx             ; Move if not equal (ZF=0)
cmovg  rax, rbx             ; Move if greater
cmovl  rax, rbx             ; Move if less

; Branchless code pattern
cmp rax, 10
cmovg rax, rbx              ; RAX = (RAX > 10) ? RBX : RAX
```

---

## String Operations

### MOVS - Move String
```asm
movsb                       ; Move byte from [RSI] to [RDI]
movsw                       ; Move word
movsd                       ; Move dword
movsq                       ; Move qword

rep movsb                   ; Repeat RCX times (memcpy)
```

**Security Issue:**
- No bounds checking!
- Can overflow if RCX is attacker-controlled

---

### STOS - Store String
```asm
stosb                       ; Store AL to [RDI]
stosw                       ; Store AX to [RDI]
stosd                       ; Store EAX to [RDI]
stosq                       ; Store RAX to [RDI]

rep stosb                   ; Repeat RCX times (memset)
```

**Example:**
```asm
; Zero buffer
lea rdi, [buffer]
xor al, al
mov rcx, 100
rep stosb                   ; memset(buffer, 0, 100)
```

---

### SCAS - Scan String
```asm
scasb                       ; Compare AL with [RDI]
rep scasb                   ; Repeat while equal
repne scasb                 ; Repeat while not equal (strlen)
```

---

### LODS - Load String
```asm
lodsb                       ; AL = [RSI], RSI++
lodsw                       ; AX = [RSI], RSI += 2
lodsd                       ; EAX = [RSI], RSI += 4
lodsq                       ; RAX = [RSI], RSI += 8
```

---

### CMPS - Compare String
```asm
cmpsb                       ; Compare [RSI] with [RDI]
repe cmpsb                  ; Repeat while equal (memcmp)
```

---

## System & Special

### SYSCALL / SYSRET
**Linux x64 Syscall:**
```asm
mov rax, syscall_number     ; System call number
mov rdi, arg1               ; 1st arg
mov rsi, arg2               ; 2nd arg
mov rdx, arg3               ; 3rd arg
mov r10, arg4               ; 4th arg (not RCX!)
mov r8, arg5                ; 5th arg
mov r9, arg6                ; 6th arg
syscall                     ; Execute syscall
```

**Windows x64 Syscall:**
```asm
mov r10, rcx                ; Save RCX to R10
mov eax, syscall_number     ; System call number
syscall                     ; Execute syscall
```

---

### INT - Software Interrupt
```asm
int 0x80                    ; Legacy Linux x86 syscall
int 3                       ; Debugger breakpoint (0xCC)
int 0x2E                    ; Legacy Windows syscall
```

---

### NOP - No Operation
```asm
nop                         ; 0x90 - do nothing for 1 cycle

; Multi-byte NOP (for alignment)
nop dword [rax]             ; 3-byte NOP
```

**Security Use:**
- NOP sleds in shellcode
- Padding in ROP chains

---

### CPUID - CPU Identification
```asm
mov eax, 0
cpuid                       ; Returns CPU info in EAX, EBX, ECX, EDX
```

**Anti-VM Detection:**
```asm
mov eax, 1
cpuid
test ecx, 0x80000000        ; Check hypervisor bit
jnz running_in_vm
```

---

### RDTSC - Read Time-Stamp Counter
```asm
rdtsc                       ; EDX:EAX = timestamp counter
```

**Anti-Debug Timing Check:**
```asm
rdtsc
mov r10, rax
; ... code to check ...
rdtsc
sub rax, r10
cmp rax, 0x10000            ; Too slow? Debugger attached?
ja debugger_detected
```

---

### LEAVE - Function Exit Helper
```asm
leave                       ; Equivalent to: mov rsp, rbp; pop rbp
```

**Common function epilogue:**
```asm
leave
ret
```

---

## Calling Conventions Summary

### Windows x64 (Microsoft)
```asm
; Integer/Pointer Arguments:
; RCX, RDX, R8, R9, [stack+0x20], [stack+0x28], ...

; Floating Point Arguments:
; XMM0, XMM1, XMM2, XMM3

; Shadow Space: 32 bytes (0x20) reserved on stack for first 4 args

; Callee-Saved: RBX, RBP, RDI, RSI, RSP, R12-R15
; Caller-Saved: RAX, RCX, RDX, R8-R11

; Example:
sub rsp, 0x28               ; Shadow space + alignment
mov rcx, arg1
mov rdx, arg2
mov r8, arg3
mov r9, arg4
mov [rsp+0x20], arg5        ; 5th arg on stack
call function
add rsp, 0x28
```

---

### Linux/macOS x64 (System V AMD64)
```asm
; Integer/Pointer Arguments:
; RDI, RSI, RDX, RCX, R8, R9, [stack], ...

; Floating Point Arguments:
; XMM0-XMM7

; No Shadow Space Required

; Callee-Saved: RBX, RBP, RSP, R12-R15
; Caller-Saved: RAX, RDI, RSI, RDX, RCX, R8-R11

; Example:
mov rdi, arg1
mov rsi, arg2
mov rdx, arg3
mov rcx, arg4
mov r8, arg5
mov r9, arg6
call function
```

---

## Security-Relevant Patterns

### ROP Gadget Recognition
```asm
pop rdi; ret                ; Load argument from stack
pop rsi; ret                ; Common ROP gadget
add rsp, 0x10; ret          ; Stack adjustment
xchg rsp, rax; ret          ; Stack pivot gadget
```

---

### Virtual Function Call (Type Confusion Target)
```asm
mov rax, [rcx]              ; Load vtable pointer
call [rax + 0x10]           ; Call virtual function at offset 0x10

; Exploitation: Control RCX to point to fake vtable
```

---

### NULL Check Bypass
```asm
test rax, rax               ; Check if NULL
jz error_path               ; Jump if NULL

; Need RAX != 0 to bypass check
```

---

### Bounds Check Bypass
```asm
cmp rdx, 0x1000             ; Check size
ja too_large                ; Jump if above 0x1000

; Need RDX <= 0x1000 to bypass (but could use integer overflow)
```

---

### Stack Canary Check
```asm
; Function prologue
mov rax, fs:[0x28]          ; Load canary (Linux)
mov [rbp-0x8], rax          ; Store on stack

; Function epilogue
mov rax, [rbp-0x8]          ; Load stored canary
xor rax, fs:[0x28]          ; Compare with original
jne __stack_chk_fail        ; Abort if mismatch
```

---

## Common Vulnerability Patterns

### No Bounds Check
```asm
mov rdi, buffer
mov rsi, user_input
call strcpy                 ; No size check!
```

### Unsafe Arithmetic
```asm
mov rax, [size_from_user]
add rax, 0x10               ; Integer overflow possible
call malloc                 ; Allocate small buffer, overflow later
```

### Use-After-Free
```asm
mov rdi, [ptr]
call free                   ; Free object

; ... later ...
mov rax, [ptr]              ; ptr still has old address
call [rax + 0x10]           ; Call freed memory
```

### Type Confusion
```asm
mov eax, [rcx]              ; Load type field
cmp eax, TYPE_ADMIN
jne not_admin
call [rcx + 0x40]           ; Assume admin vtable layout
```

---

## Quick Reference Card

### Essential Instructions
```
mov   - Move data
lea   - Load effective address (no dereference)
push  - Push to stack
pop   - Pop from stack
call  - Call function
ret   - Return from function
jmp   - Unconditional jump
je/jne - Jump if equal/not equal
cmp   - Compare (sets flags)
test  - Bitwise AND (sets flags)
add   - Addition
sub   - Subtraction
xor   - XOR (clear register: xor rax, rax)
```

### Key Registers (x64)
```
RAX   - Return value
RDI   - 1st arg (Linux)
RSI   - 2nd arg (Linux)
RDX   - 3rd arg (Linux)
RCX   - 1st arg (Windows), 4th arg (Linux)
R8    - 3rd arg (Windows), 5th arg (Linux)
R9    - 4th arg (Windows), 6th arg (Linux)
RBP   - Frame pointer
RSP   - Stack pointer
RIP   - Instruction pointer
```

### Memory Sizes
```
BYTE   - 1 byte  (8-bit)   - AL, BL, CL, etc.
WORD   - 2 bytes (16-bit)  - AX, BX, CX, etc.
DWORD  - 4 bytes (32-bit)  - EAX, EBX, ECX, etc.
QWORD  - 8 bytes (64-bit)  - RAX, RBX, RCX, etc.
```

---

*This reference covers the most important x86/x86_64 instructions and patterns for vulnerability research and exploitation.*
