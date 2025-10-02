# PWN Challenge Manual Checklist

A comprehensive manual for solving binary exploitation challenges with systematic methodology and thinking process.

---

## Phase 1: Initial Reconnaissance

### Basic File Analysis
- [ ] Run `file <binary>` - Check architecture (32/64-bit), stripped/not stripped
- [ ] Run `checksec <binary>` - Identify enabled protections
  - [ ] CANARY - Stack canary enabled?
  - [ ] FORTIFY - Fortified functions?
  - [ ] NX - Non-executable stack/heap?
  - [ ] PIE - Position Independent Executable?
  - [ ] RELRO - Full/Partial/No RELRO?
- [ ] Check file size and complexity
- [ ] Identify libc version if provided

**💭 Thinking Point:** What protections are enabled? This determines which exploitation techniques are viable.

### Running the Binary
- [ ] Execute binary normally - observe behavior
- [ ] Test with various inputs (long strings, special chars, numbers)
- [ ] Note any prompts, menu options, or user interactions
- [ ] Check for output/input patterns
- [ ] Test error handling

**💭 Thinking Point:** What does the program expect? What happens with unexpected input?

---

## Phase 2: Static Analysis

### Disassembly & Decompilation
- [ ] Open in disassembler (IDA/Ghidra/Binary Ninja)
- [ ] Identify main function and entry point
- [ ] Map out function call graph
- [ ] Identify interesting functions:
  - [ ] String manipulation (strcpy, gets, scanf, sprintf, strcat)
  - [ ] Memory operations (malloc, free, read, write)
  - [ ] System/exec functions
  - [ ] Custom functions (win, backdoor, admin, etc.)
- [ ] Look for hardcoded values, buffers, addresses

**💭 Thinking Point:** What's the program's logic flow? Where does user input go?

### Code Review Checklist
- [ ] Identify all user input points
- [ ] Check buffer sizes vs input lengths
- [ ] Look for dangerous function calls
- [ ] Check integer arithmetic (potential overflows)
- [ ] Identify format string usage
- [ ] Look for pointer arithmetic
- [ ] Check array/buffer indexing
- [ ] Review heap operations (malloc/free patterns)

**💭 Thinking Point:** Where can I inject malicious input? What's the vulnerability surface?

---

## Phase 3: Vulnerability Identification

### Stack Vulnerabilities
- [ ] **Buffer Overflow** - Can I write past buffer boundaries?
  - Check strcpy, gets, scanf without size limit
  - Compare buffer size with read length
- [ ] **Format String** - Is printf/sprintf called with user input?
  - Test with `%x %p %s` patterns
  - Can read/write arbitrary memory?
- [ ] **Off-by-One** - Single byte overflow possible?
- [ ] **Stack Pivoting** - Can I control RSP/ESP?

**💭 Design Logic:** If overflow exists, what can I overwrite? Return address? Function pointer? Canary?

### Heap Vulnerabilities
- [ ] **Use-After-Free** - Is memory accessed after free?
- [ ] **Double Free** - Can same chunk be freed twice?
- [ ] **Heap Overflow** - Can I overflow into adjacent chunks?
- [ ] **Type Confusion** - Different types using same memory?
- [ ] **Uninitialized Memory** - Using malloc'd data without init?

**💭 Design Logic:** What's the heap layout? Can I manipulate chunk metadata?

### Logic Vulnerabilities
- [ ] **Integer Overflow** - Can arithmetic wrap around?
- [ ] **Race Condition** - Time-of-check to time-of-use?
- [ ] **Authentication Bypass** - Logic flaws in checks?
- [ ] **Array Index** - Out-of-bounds read/write?

**💭 Design Logic:** Are there edge cases in the logic? What assumptions does the code make?

---

## Phase 4: Dynamic Analysis

### Debugging Setup
- [ ] Set up GDB with pwndbg/gef/peda
- [ ] Create breakpoints at key functions
- [ ] Prepare test inputs

### Crash Analysis
- [ ] Trigger the vulnerability
- [ ] Check crash location and registers
- [ ] Analyze stack/heap state at crash
- [ ] Calculate offset to control RIP/EIP
- [ ] Verify control of registers

**💭 Thinking Point:** What do I control at crash? Can I redirect execution?

### Pattern Finding
- [ ] Use cyclic patterns to find exact offsets
  - `cyclic 200` in pwntools
  - `pattern create 200` in pwndbg
- [ ] Calculate offset with `cyclic -l <value>`
- [ ] Verify offset with custom payload

**💭 Thinking Point:** How many bytes until I overwrite the return address?

---

## Phase 5: Exploitation Strategy

### Choose Attack Vector

#### Stack-Based Exploitation Decision Tree

**If NX Enabled:**
- [ ] **ret2win** - Win function exists in binary?
- [ ] **ret2plt** - Need to call system() via PLT?
- [ ] **ret2libc** - Need to leak libc and use gadgets?
- [ ] **ROP Chain** - Build gadget chain for complex operations
- [ ] **SROP** - Sigreturn available for syscall?

**If NX Disabled:**
- [ ] **Shellcode Injection** - Inject and execute shellcode
- [ ] **Egg Hunter** - Limited space, hunt for shellcode

**If Canary Enabled:**
- [ ] **Canary Leak** - Format string or info leak?
- [ ] **Canary Bypass** - Fork/thread without re-randomization?
- [ ] **Overwrite with Leaked Value** - Restore canary before return

**If PIE Enabled:**
- [ ] **Address Leak** - Info leak to defeat PIE?
- [ ] **Partial Overwrite** - Overwrite only lower bytes
- [ ] **Brute Force** - ASLR bits brute-forceable?

**💭 Design Logic:** What's the exploitation path with least resistance?

#### Heap-Based Exploitation Decision Tree

**For UAF:**
- [ ] **Object Replacement** - Replace freed object with controlled data
- [ ] **Vtable Hijack** - C++ virtual function pointers
- [ ] **Function Pointer Overwrite** - Control execution

**For Double Free:**
- [ ] **tcache Dup** - Fast allocation for arbitrary write
- [ ] **Fastbin Dup** - Older libc versions

**For Heap Overflow:**
- [ ] **Chunk Overlap** - Create overlapping chunks
- [ ] **tcache Poisoning** - Corrupt fd pointer
- [ ] **Fastbin Attack** - Corrupt fastbin
- [ ] **Unsorted Bin Attack** - Arbitrary write primitive

**💭 Design Logic:** What primitives do I have? Read? Write? Execute?

---

## Phase 6: Information Leaks

### Leak Strategy
- [ ] Identify leak opportunity:
  - [ ] Format string vulnerability
  - [ ] Out-of-bounds read
  - [ ] Uninitialized memory
  - [ ] Partial overwrite revealing data
- [ ] Determine what to leak:
  - [ ] Stack canary
  - [ ] Libc base address
  - [ ] Binary base (PIE)
  - [ ] Heap address
  - [ ] Stack address

### Common Leak Targets
- [ ] **GOT Entry** - Leak libc function address
- [ ] **Canary** - At rbp-0x8 typically
- [ ] **Return Address** - Reveals binary/libc base
- [ ] **Environment Variables** - May contain addresses

**💭 Thinking Point:** What addresses do I need to calculate my target?

---

## Phase 7: Exploit Development

### Build Exploit Template

```python
from pwn import *

# Configuration
binary = './challenge'
libc = ELF('./libc.so.6') if exists('./libc.so.6') else None
elf = ELF(binary)
context.binary = elf
context.log_level = 'debug'

# Connection
def conn():
    if args.REMOTE:
        return remote('host', 1337)
    else:
        return process(binary)

# Exploit
def exploit():
    io = conn()

    # Stage 1: Information Leak
    # TODO: Implement leak

    # Stage 2: Build Payload
    # TODO: Build ROP/payload

    # Stage 3: Trigger Vulnerability
    # TODO: Send exploit

    io.interactive()

if __name__ == '__main__':
    exploit()
```

### Exploit Development Checklist
- [ ] **Stage 1: Information Gathering**
  - [ ] Leak required addresses
  - [ ] Calculate base addresses
  - [ ] Find gadgets/one-gadgets

- [ ] **Stage 2: Payload Construction**
  - [ ] Build ROP chain
  - [ ] Prepare shellcode (if NX disabled)
  - [ ] Calculate offsets
  - [ ] Handle alignment requirements

- [ ] **Stage 3: Execution**
  - [ ] Send payload
  - [ ] Handle program flow
  - [ ] Trigger vulnerability at right time

- [ ] **Stage 4: Post-Exploitation**
  - [ ] Verify shell/code execution
  - [ ] Read flag
  - [ ] Clean up/maintain stability

**💭 Design Logic:** Break exploit into stages. Test each stage independently.

---

## Phase 8: Common Techniques Reference

### Stack Exploitation Techniques

#### ret2win
```
- Find "win" function address
- Overflow to return address
- Overwrite with win function
```
**When to use:** Win/backdoor function exists, no/weak protections

#### ret2plt
```
- Use PLT entries to call libc functions
- Chain calls: puts@plt to leak, system@plt to execute
```
**When to use:** Need libc functions, no libc base yet

#### ret2libc
```
- Leak libc address (GOT entry)
- Calculate libc base
- Find system/execve/one-gadget
- Build ROP chain
```
**When to use:** NX enabled, need shell, libc available

#### ROP Chain Construction
```
- Find gadgets: ROPgadget, ropper
- Common gadgets needed:
  * pop rdi; ret (1st arg)
  * pop rsi; ret (2nd arg)
  * pop rdx; ret (3rd arg)
  * pop rax; ret (syscall number)
  * syscall; ret
- Chain together for desired operation
```
**When to use:** Complex operations needed, NX enabled

### Heap Exploitation Techniques

#### tcache Poisoning
```
- Free chunk into tcache
- Overflow to corrupt fd pointer
- Point fd to target address
- Allocate twice to get arbitrary write
```
**When to use:** Libc 2.26+, heap overflow/UAF available

#### Fastbin Attack
```
- Free chunk into fastbin
- Overflow to corrupt fd
- Forge chunk size at target
- Allocate to get chunk at target
```
**When to use:** Older libc, small allocations

#### House of Force
```
- Overflow top chunk size to -1
- Allocate large size to move top chunk
- Next allocation at target address
```
**When to use:** Can corrupt top chunk, calculate distances

#### Use-After-Free Pattern
```
- Allocate object
- Free object
- Allocate new object same size
- Use old pointer to manipulate new object
```
**When to use:** Objects with function pointers, C++ vtables

### Format String Exploitation

#### Reading Memory
```
%x     - Read from stack (32-bit)
%p     - Read pointer from stack
%s     - Read string at address
%n$p   - Read nth argument
```

#### Writing Memory
```
%n     - Write number of bytes printed
%hn    - Write 2 bytes
%hhn   - Write 1 byte
%<n>c  - Print n characters (pad for value)
```

**When to use:** printf(user_input) pattern exists

---

## Phase 9: Protection Bypass Strategies

### ASLR Bypass
- [ ] **Information Leak** - Leak any address, calculate base
- [ ] **Partial Overwrite** - Overwrite only lower bytes (12 bits static)
- [ ] **Brute Force** - If remote service restarts without re-rand
- [ ] **No PIE** - Binary base static, leverage that

### Stack Canary Bypass
- [ ] **Leak Canary** - Format string, out-of-bounds read
- [ ] **Overwrite and Restore** - Leak then write back
- [ ] **Fork without Re-rand** - Brute force byte-by-byte
- [ ] **Stack Pivot** - Change stack pointer before canary check

### NX/DEP Bypass
- [ ] **ROP** - Reuse existing code
- [ ] **ret2libc** - Use libc functions
- [ ] **mprotect** - Make memory executable via ROP
- [ ] **sigreturn** - SROP for syscalls

### PIE Bypass
- [ ] **Leak Binary Address** - Any code pointer
- [ ] **Format String** - Read saved return addresses
- [ ] **Partial Overwrite** - Lower 12 bits predictable

### RELRO Bypass
- [ ] **No RELRO** - Direct GOT overwrite
- [ ] **Partial RELRO** - GOT writable, overwrite entries
- [ ] **Full RELRO** - Cannot overwrite GOT, use other methods

---

## Phase 10: Tools & Commands

### Analysis Tools
```bash
# File information
file <binary>
checksec <binary>
strings <binary>
rabin2 -I <binary>

# Disassembly
objdump -d <binary>
r2 -A <binary>

# Library identification
ldd <binary>
./libc-database/identify <libc>
```

### Debugging
```bash
# GDB with extensions
gdb <binary> -ex 'source /path/to/pwndbg/gdbinit.py'
gdb <binary> -ex 'source /path/to/gef/gef.py'

# Useful GDB commands
b main                 # Breakpoint
r < input.txt         # Run with input
c                     # Continue
ni / si               # Next/step instruction
x/20wx $rsp          # Examine stack
telescope $rsp       # Stack dump (pwndbg)
vmmap                # Memory mappings
```

### ROP Gadget Finding
```bash
# ROPgadget
ROPgadget --binary <binary>
ROPgadget --binary <binary> --only "pop|ret"

# ropper
ropper --file <binary>
ropper --file <binary> --search "pop rdi"

# one_gadget (for libc)
one_gadget <libc.so>
```

### Pwntools Scripts
```python
# Cyclic patterns
cyclic(200)           # Generate pattern
cyclic_find(0x61616161)  # Find offset

# ROP
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])

# Packing
p64(0xdeadbeef)      # Pack 64-bit
u64(data)            # Unpack 64-bit

# Shellcode
shellcraft.sh()      # Generate shellcode
asm(shellcraft.sh()) # Assemble shellcode
```

---

## Phase 11: Methodical Approach

### The Scientific Method for Pwn

1. **Observe** - What does the program do?
2. **Hypothesize** - Where might the vulnerability be?
3. **Experiment** - Can I trigger abnormal behavior?
4. **Analyze** - What happened and why?
5. **Exploit** - Can I control execution?
6. **Iterate** - Refine until working exploit

### Common Debugging Questions

**When stuck on crashes:**
- What instruction causes the crash?
- What registers do I control?
- Is the crash at a ret instruction?
- What's on the stack at crash time?

**When exploit doesn't work:**
- Am I sending data correctly?
- Are there null bytes breaking my payload?
- Is alignment correct? (16-byte for movaps)
- Did ASLR change addresses?
- Are my offsets correct?

**When leaks don't work:**
- Am I reading from the right offset?
- Is the pointer valid?
- Am I parsing the leaked data correctly?
- Is endianness correct?

### Exploit Iteration Process

```
1. Crash the program ✓
2. Control RIP/EIP ✓
3. Bypass protections (canary, PIE, etc.)
4. Leak required addresses
5. Build working payload
6. Get shell locally
7. Test on remote
8. Capture flag
```

---

## Phase 12: Advanced Techniques

### FSOP (File Stream Oriented Programming)
- [ ] Identify FILE structure usage (fopen, fclose, fread, fwrite)
- [ ] Corrupt FILE structure vtable
- [ ] Point vtable to controlled memory
- [ ] Trigger file operation for code execution

**💭 Design Logic:** FILE structures contain function pointers, hijacking them gives execution control

### One-Gadget Usage
```bash
# Find one-gadgets in libc
one_gadget libc.so.6

# Common constraints:
# - [rsp+0x30] == NULL
# - [rsp+0x50] == NULL
# - rcx == NULL

# Try multiple one-gadgets if constraints not met
```

**💭 Design Logic:** One-gadget = single libc address that spawns shell, but has constraints

### ret2csu
```
# Use __libc_csu_init gadgets for argument control
# When few gadgets available, csu provides:
# - pop rbx, rbp, r12, r13, r14, r15
# - controlled call via r13

# Useful in statically linked or gadget-poor binaries
```

### SROP (Sigreturn Oriented Programming)
```
# When rt_sigreturn syscall available:
# 1. Build fake sigreturn frame
# 2. Set all registers via frame
# 3. Execute syscall for complete control

# Useful when few gadgets but sigreturn available
```

---

## Phase 13: Common Pitfalls & Tips

### Pitfalls to Avoid
- [ ] **Null Bytes** - String functions stop at null, use after final input
- [ ] **Alignment** - x64 requires 16-byte alignment before calls (movaps)
- [ ] **Buffering** - Add `io.recvline()` to sync program state
- [ ] **Wrong Libc** - Verify libc version matches server
- [ ] **Off-by-One in Offset** - Double-check with cyclic patterns
- [ ] **Endianness** - Use p64/p32, not manual packing
- [ ] **Gadget Side Effects** - Check what else gadget does

### Pro Tips
- [ ] Always test exploits multiple times (ASLR randomness)
- [ ] Use `context.log_level = 'debug'` to see all I/O
- [ ] Save leaked addresses for later stages
- [ ] Keep exploit modular (leak stage, exploit stage)
- [ ] Comment your exploit code
- [ ] Test locally before trying remote
- [ ] Use `io.interactive()` to debug post-exploitation
- [ ] Keep a collection of working exploits as templates

### Debugging Techniques
```python
# Attach GDB mid-exploit
io = process('./binary')
gdb.attach(io, '''
    b *0x401234
    c
''')

# Pause to manually debug
io = process('./binary')
pause()  # Manually attach Gdb with: gdb -p <pid>

# Print addresses for verification
log.info(f"Leaked libc base: {hex(libc_base)}")
log.info(f"System address: {hex(system)}")
```

---

## Phase 14: CTF-Specific Strategies

### Time Management
- [ ] **Quick Wins First** - Sort challenges by difficulty
- [ ] **Pattern Recognition** - Similar to past challenges?
- [ ] **Hint Hunting** - Challenge name, description, tags
- [ ] **Know When to Switch** - Don't get stuck on one challenge

### Team Collaboration
- [ ] **Share Findings** - Document what you discover
- [ ] **Divide Tasks** - One reverse, one exploit, one research
- [ ] **Template Reuse** - Share working exploit templates

### Challenge Reconnaissance
- [ ] Check challenge name for hints (e.g., "babyheap", "ret2where")
- [ ] Read description carefully
- [ ] Note provided files (libc, ld.so provided = remote versions)
- [ ] Check for source code
- [ ] Look for challenge author patterns

---

## Quick Reference: Exploit Decision Tree

```
START: I have a pwn binary
│
├─→ Can I crash it? → No → Find vulnerability (static analysis)
│                   → Yes ↓
│
├─→ Do I control RIP/RBP? → No → Find offset or different vuln
│                        → Yes ↓
│
├─→ Is there a win function? → Yes → ret2win
│                           → No ↓
│
├─→ Is NX enabled? → No → Shellcode injection
│                 → Yes ↓
│
├─→ Is libc provided? → Yes → ret2libc (leak + system/execve)
│                    → No → ret2plt or ROP syscalls
│
├─→ Is PIE enabled? → Yes → Need info leak first
│                  → No ↓
│
├─→ Is canary enabled? → Yes → Need canary leak first
│                     → No ↓
│
└─→ BUILD EXPLOIT
```

---

## Checklist Summary

Before submitting exploit:
- [ ] Works locally multiple times
- [ ] Handles ASLR (if applicable)
- [ ] Tested with correct libc
- [ ] Code is clean and commented
- [ ] No hardcoded addresses that change
- [ ] IO synchronization correct
- [ ] Tested on remote (if possible)

**Final Thought:** Pwn challenges are puzzles. Break them into steps, test each step, and build systematically. When stuck, go back to basics: What do I control? What do I need? How do I get there?

---

## Additional Resources

- **Practice Platforms:** pwnable.kr, pwnable.tw, ROP Emporium, exploit.education
- **Learning:** Nightmare, pwn.college, LiveOverflow videos
- **Tools:** pwntools documentation, GDB cheatsheets
- **Reference:** Linux syscall table, shellcode database, libc-database

---

*Good luck and happy pwning! 🚩*
