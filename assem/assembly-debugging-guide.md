# Assembly Debugging Guide - Hello World to Exploitation

## Overview
This guide walks through practical assembly debugging, starting from a simple hello world program and progressing to understanding buffer overflow exploitation patterns.

---

## Part 1: Hello World Assembly Analysis

### Source Code
```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

### Compilation
```bash
gcc -g -o hello hello.c
```

### Disassembly Output
```asm
hello`main:
hello[0x100000470] <+0>:  pushq  %rbp
hello[0x100000471] <+1>:  movq   %rsp, %rbp
hello[0x100000474] <+4>:  subq   $0x10, %rsp
hello[0x100000478] <+8>:  movl   $0x0, -0x4(%rbp)
hello[0x10000047f] <+15>: leaq   0x16(%rip), %rdi          ; "Hello, World!\n"
hello[0x100000486] <+22>: movb   $0x0, %al
hello[0x100000488] <+24>: callq  0x100000496               ; symbol stub for: printf
hello[0x10000048d] <+29>: xorl   %eax, %eax
hello[0x10000048f] <+31>: addq   $0x10, %rsp
hello[0x100000493] <+35>: popq   %rbp
hello[0x100000494] <+36>: retq
```

### Pattern 1: Function Prologue (CRITICAL)
```asm
pushq  %rbp              ; Save old frame pointer
movq   %rsp, %rbp        ; Set up new frame (rbp = rsp)
subq   $0x10, %rsp       ; Allocate 0x10 bytes for local variables
```

**Security Insight:**
- Distance from local variables to saved rbp = 0x10 bytes
- If you overflow a buffer here, you need 0x10 bytes to reach saved rbp
- Then 8 more bytes to reach the return address

### Pattern 2: Calling Convention (macOS/Linux x64)
```asm
leaq   0x16(%rip), %rdi  ; Load address into RDI (1st argument!)
                         ; RIP-relative addressing (for ASLR)
movb   $0x0, %al         ; Varargs convention (0 vector args)
callq  0x100000496       ; Call printf
```

**CRITICAL:**
- On macOS/Linux: 1st arg = RDI, 2nd = RSI, 3rd = RDX, 4th = RCX
- On Windows: 1st arg = RCX, 2nd = RDX, 3rd = R8, 4th = R9
- **Always verify calling convention for your target platform!**

### Pattern 3: Function Epilogue (EXPLOITATION POINT)
```asm
xorl   %eax, %eax        ; Set return value to 0 (xor is faster than mov)
addq   $0x10, %rsp       ; Deallocate local variables
popq   %rbp              ; Restore old frame pointer
retq                     ; Return (pops address from stack!)
```

**Security Insight:**
- `retq` is where ROP chains happen
- Stack must contain: [return_addr][gadget1][gadget2]...
- Controlling the return address = code execution

### Register State at Breakpoint

```bash
lldb hello -o "b main" -o "run" -o "register read"
```

**Output:**
```
General Purpose Registers:
       rax = 0x00007ff8481329c0
       rbx = 0x00007ff848132dd0
       rcx = 0x00007ff7bfefee28
       rdx = 0x00007ff7bfefebf0
       rdi = 0x0000000000000001
       rsi = 0x00007ff7bfefebe0
       rbp = 0x00007ff7bfefe540    ← Frame pointer
       rsp = 0x00007ff7bfefe530    ← Stack pointer
       rip = 0x000000010000047f    ← Instruction pointer
```

**Key Observations:**
- `rsp` (stack pointer) = `0x00007ff7bfefe530`
- `rbp` (frame pointer) = `0x00007ff7bfefe540` (16 bytes above rsp)
- `rip` (instruction pointer) = `0x000000010000047f` (about to execute printf)

### Stack Memory Layout

```bash
lldb hello -o "b main" -o "run" -o "x/10gx $rsp"
```

**Output:**
```
Address              Value                    Meaning
─────────────────────────────────────────────────────────
0x7ff7bfefe530  →  0x00007ff848151ce0       [Local variables area]
0x7ff7bfefe538  →  0x0000000048132dd0
0x7ff7bfefe540  →  0x00007ff7bfefebc0       ← RBP points here (saved RBP)
0x7ff7bfefe548  →  0x00007ff806fa8781       ← RETURN ADDRESS (critical!)
```

**EXPLOITATION INSIGHT:**
- If you overflow starting at `0x7ff7bfefe530`
- After 0x10 bytes (16 bytes), you hit saved RBP
- After 0x18 bytes (24 bytes), you hit **return address**
- **Controlling return address = code execution!**

---

## Part 2: Vulnerable Program Analysis

### Source Code
```c
#include <stdio.h>
#include <string.h>

void win() {
    printf("🎉 You hijacked execution!\n");
}

void vulnerable() {
    char buffer[16];
    printf("Buffer at: %p\n", buffer);
    printf("win() at: %p\n", win);
    printf("Enter input: ");
    gets(buffer);  // VULNERABLE: No bounds checking!
    printf("You entered: %s\n", buffer);
}

int main() {
    printf("=== Stack Overflow Demo ===\n");
    vulnerable();
    printf("Program exiting normally.\n");
    return 0;
}
```

### Compilation
```bash
gcc -g -fno-stack-protector -Wno-deprecated-declarations -o vuln vuln.c
```

**Flags explained:**
- `-g`: Include debug symbols
- `-fno-stack-protector`: Disable stack canaries (for learning purposes)
- `-Wno-deprecated-declarations`: Suppress warnings about `gets()`

### Disassembly of vulnerable()

```bash
lldb vuln -o "disassemble --name vulnerable"
```

**Output:**
```asm
vuln`vulnerable:
vuln[0x100000490] <+0>:  pushq  %rbp
vuln[0x100000491] <+1>:  movq   %rsp, %rbp
vuln[0x100000494] <+4>:  subq   $0x10, %rsp              ; Allocate 16 bytes
vuln[0x100000498] <+8>:  leaq   -0x10(%rbp), %rsi        ; Load buffer address
vuln[0x10000049c] <+12>: leaq   0xaf(%rip), %rdi         ; "Buffer at: %p\n"
vuln[0x1000004a3] <+19>: movb   $0x0, %al
vuln[0x1000004a5] <+21>: callq  0x10000052e              ; printf
vuln[0x1000004aa] <+26>: leaq   0xb0(%rip), %rdi         ; "win() at: %p\n"
vuln[0x1000004b1] <+33>: leaq   -0x48(%rip), %rsi        ; win address
vuln[0x1000004b8] <+40>: movb   $0x0, %al
vuln[0x1000004ba] <+42>: callq  0x10000052e              ; printf
vuln[0x1000004bf] <+47>: leaq   0xa9(%rip), %rdi         ; "Enter input: "
vuln[0x1000004c6] <+54>: movb   $0x0, %al
vuln[0x1000004c8] <+56>: callq  0x10000052e              ; printf
vuln[0x1000004cd] <+61>: leaq   -0x10(%rbp), %rdi        ; Load buffer address
vuln[0x1000004d1] <+65>: callq  0x100000528              ; gets() - VULNERABLE!
vuln[0x1000004d6] <+70>: leaq   -0x10(%rbp), %rsi
vuln[0x1000004da] <+74>: leaq   0x9c(%rip), %rdi         ; "You entered: %s\n"
vuln[0x1000004e1] <+81>: movb   $0x0, %al
vuln[0x1000004e3] <+83>: callq  0x10000052e              ; printf
vuln[0x1000004e8] <+88>: addq   $0x10, %rsp
vuln[0x1000004ec] <+92>: popq   %rbp
vuln[0x1000004ed] <+93>: retq
```

### Vulnerability Location
```asm
subq   $0x10, %rsp           ; Allocate 16 bytes for locals
leaq   -0x10(%rbp), %rdi     ; Load buffer address (rbp-0x10)
callq  gets                  ; DANGEROUS: No bounds check!
```

### Exploitation Math
```
Buffer location: rbp - 0x10 (16 bytes before rbp)
Saved rbp:       rbp + 0x0
Return address:  rbp + 0x8

Total offset from buffer to return address: 0x10 + 0x8 = 0x18 (24 bytes)
```

### Stack Layout Visualization

```
[Lower Memory Addresses]
    ↓
rbp-0x10:  buffer[0]      ← Start of 16-byte buffer
rbp-0x0f:  buffer[1]
rbp-0x0e:  buffer[2]
   ...
rbp-0x01:  buffer[15]     ← End of buffer
rbp+0x00:  saved rbp      ← 8 bytes (old frame pointer)
rbp+0x08:  return address ← 8 bytes (TARGET!)
    ↑
[Higher Memory Addresses]
```

**Exploitation Strategy:**
1. Write 16 bytes to fill the buffer
2. Write 8 bytes to overwrite saved rbp (can be garbage)
3. Write 8 bytes to overwrite return address (address of `win()`)

### Running the Program

```bash
echo "AAAA" | ./vuln
```

**Output:**
```
=== Stack Overflow Demo ===
Buffer at: 0x7ff7b2368780
win() at: 0x10db96470
Enter input: You entered: AAAA
Program exiting normally.
```

**Key Information:**
- The program prints the buffer address
- The program prints the `win()` function address
- These are the values you need for exploitation!

---

## Assembly Patterns Summary

### 1. Control Flow Instructions (Must Recognize)
```asm
call rax        ; Can I control rax? = code execution
jmp [rcx+0x10]  ; Can I control rcx? = hijack flow
ret             ; Stack control = ROP chain possible
ret 0x10        ; Stack cleanup, adjust ROP accordingly

; Conditional jumps
je/jne          ; Can I influence zero flag?
test rax, rax   ; Checking for NULL
jz fail_path    ; Need rax = non-zero to avoid failure
```

### 2. Memory Access Patterns
```asm
mov rax, [rcx]      ; Arbitrary read if you control rcx
mov [rcx], rax      ; Arbitrary write if you control rcx
mov rax, [rcx+rdx*8] ; Array indexing - control rdx = out-of-bounds

; String operations (common overflow sources)
rep movsb           ; memcpy equivalent - NO bounds checking
rep stosb           ; memset equivalent - NO bounds checking
```

### 3. Stack Frame Operations
```asm
; Prologue
push rbp         ; Save old base
mov rbp, rsp     ; New frame
sub rsp, 0x30    ; Local variables (0x30 bytes)

; Epilogue
leave            ; mov rsp, rbp; pop rbp
ret              ; Your exploitation point

; Stack pivoting (advanced)
xchg rsp, rax    ; If I control rax, I control stack
mov rsp, [rcx]   ; Arbitrary stack pivot
```

---

## Critical Questions to Ask When Analyzing Assembly

1. **Can I control this register?**
   - If yes, what instructions use it?
   - Can it be used for memory access?
   - Can it be used for control flow?

2. **Where is this buffer in memory?**
   - Relative to RBP/RSP?
   - What's above/below it on the stack?
   - How many bytes to reach return address?

3. **Is there a bounds check?**
   - Look for `cmp` followed by conditional jump
   - Does the function validate size before copy?
   - Are there any sanitizer checks?

4. **What's the calling convention?**
   - Linux/macOS: RDI, RSI, RDX, RCX, R8, R9
   - Windows: RCX, RDX, R8, R9
   - Additional args on stack

5. **What happens at function exit?**
   - Does it use `leave; ret`?
   - Is there exception handling (SEH)?
   - Are there stack canaries?

---

## Debugging Workflow

### Step 1: Disassemble the Target Function
```bash
lldb binary -o "disassemble --name function_name" -o "quit"
```

### Step 2: Set Breakpoint and Run
```bash
lldb binary -o "b function_name" -o "run" -o "quit"
```

### Step 3: Examine Registers
```bash
lldb binary -o "b function_name" -o "run" -o "register read" -o "quit"
```

### Step 4: Examine Stack Memory
```bash
lldb binary -o "b function_name" -o "run" -o "x/20gx $rsp" -o "quit"
```

### Step 5: Step Through Instructions
```bash
lldb binary
(lldb) b function_name
(lldb) run
(lldb) ni          # Step one instruction
(lldb) register read
(lldb) x/10gx $rsp
```

---

## Key Takeaways

1. **Function Prologue/Epilogue** - Always look for these patterns to understand stack layout
2. **Buffer Location** - Calculate using `rbp` or `rsp` offsets from assembly
3. **Return Address** - Typically at `rbp + 8` on x64
4. **Calling Convention** - CRITICAL: Linux/macOS ≠ Windows
5. **Dangerous Functions** - `gets()`, `strcpy()`, `memcpy()` without bounds checks
6. **Exploitation Point** - The `ret` instruction is where control flow hijacking happens

---

## Next Steps

- Practice calculating offsets from assembly
- Learn to identify ROP gadgets
- Understand modern mitigations (ASLR, DEP, CFG)
- Study Windows-specific patterns (SEH, PEB/TEB)
- Explore kernel exploitation primitives

---

## Tools Reference

### LLDB Commands
```bash
# Disassembly
disassemble --name function_name
di -n function_name

# Breakpoints
b function_name
b *0x address

# Execution control
run
ni                 # Next instruction
si                 # Step into
c                  # Continue

# Memory examination
x/10gx $rsp       # 10 giant (8-byte) words in hex
x/10wx $rsp       # 10 words (4-byte) in hex
x/10i $rip        # 10 instructions at rip

# Register examination
register read
register read rax
register write rax 0x41414141

# Info
frame info
thread backtrace
```

### Useful GCC/Clang Flags
```bash
-g                      # Debug symbols
-fno-stack-protector   # Disable stack canaries
-z execstack           # Executable stack (Linux)
-no-pie                # Disable PIE
-static                # Static linking
```

---

## Resources

- **Intel x64 Manual**: Official instruction reference
- **Windows Internals**: Understanding Windows architecture
- **Practical Binary Analysis**: Great book for assembly/reversing
- **LiveOverflow YouTube**: Excellent exploitation tutorials
- **pwn.college**: Interactive exploitation challenges

---

*This guide was created through hands-on debugging sessions. All examples are from actual compiled programs on macOS x64.*
