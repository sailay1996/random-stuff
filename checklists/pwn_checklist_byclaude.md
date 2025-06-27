# Complete PWN CTF Binary Exploitation Checklist

## 🔍 Initial Reconnaissance

### File Analysis
- [ ] Run `file` command to identify file type and architecture
- [ ] Check `checksec` output for security mitigations
- [ ] Examine file permissions and size
- [ ] Identify if it's statically or dynamically linked (`ldd`)
- [ ] Check for debug symbols (`objdump -h` or `readelf -S`)

### Binary Information Gathering
- [ ] Determine architecture (x86, x64, ARM, etc.)
- [ ] Identify endianness (little/big endian)
- [ ] Check for packing/obfuscation (`strings`, entropy analysis)
- [ ] Look for interesting strings (`strings -a`)
- [ ] Examine entry point and main function locations

## 🛡️ Security Mitigations Assessment

### Modern Protections
- [ ] **ASLR** - Address Space Layout Randomization
- [ ] **PIE** - Position Independent Executable
- [ ] **NX/DEP** - Non-Executable stack/heap
- [ ] **Stack Canaries** - Stack buffer overflow protection
- [ ] **RELRO** - Relocation Read-Only (Partial/Full)
- [ ] **FORTIFY_SOURCE** - Enhanced buffer overflow detection

### Bypass Strategy Planning
- [ ] Identify which protections are enabled
- [ ] Plan bypass techniques for each enabled protection
- [ ] Look for information leaks to defeat ASLR/PIE
- [ ] Check for ROP/JOP gadgets if NX is enabled

## 🔧 Static Analysis Phase

### Disassembly & Code Review
- [ ] Load in disassembler (Ghidra, IDA Pro, Radare2, Binary Ninja)
- [ ] Identify main function and program flow
- [ ] Map out all user-controlled input points
- [ ] Look for dangerous functions (`strcpy`, `gets`, `scanf`, `printf`, etc.)
- [ ] Analyze custom functions for vulnerabilities
- [ ] Check for format string vulnerabilities

### Vulnerability Hunting
- [ ] **Buffer Overflows** - Stack and heap based
- [ ] **Format String Bugs** - `printf` family functions
- [ ] **Integer Overflows** - Size calculations, array indexing
- [ ] **Use-After-Free** - Dangling pointer usage
- [ ] **Double Free** - Multiple calls to `free()`
- [ ] **Off-by-One** - Boundary condition errors
- [ ] **Race Conditions** - Multi-threaded applications

## 🏃 Dynamic Analysis Phase

### Debugging Setup
- [ ] Set up debugging environment (GDB with pwndbg/GEF/peda)
- [ ] Create test cases for normal program behavior
- [ ] Set breakpoints at critical functions
- [ ] Prepare payload delivery mechanism

### Crash Analysis
- [ ] Trigger crashes with various inputs
- [ ] Analyze crash dumps and register states
- [ ] Determine controllable registers (RIP/EIP, RSP/ESP, etc.)
- [ ] Calculate exact offset to control instruction pointer
- [ ] Verify payload space limitations

### Memory Layout Analysis
- [ ] Map memory regions (stack, heap, libraries, binary)
- [ ] Identify gadget locations for ROP chains
- [ ] Look for writable memory regions
- [ ] Check for executable memory areas

## 🎯 Exploitation Strategy

### Basic Exploitation Techniques
- [ ] **Stack Buffer Overflow** - Overwrite return address
- [ ] **Heap Exploitation** - Malloc/free abuse
- [ ] **Format String Exploitation** - Memory read/write primitives
- [ ] **Integer Overflow Exploitation** - Bypass size checks
- [ ] **Return-to-libc** - Call system functions directly

### Advanced Techniques
- [ ] **ROP (Return-Oriented Programming)** - Chain gadgets together
- [ ] **JOP (Jump-Oriented Programming)** - Jump-based code reuse
- [ ] **SROP (Sigreturn-Oriented Programming)** - Syscall-based exploitation
- [ ] **Heap Feng Shui** - Manipulate heap layout
- [ ] **House of Techniques** - Advanced heap exploitation methods

## 🧰 Tool Selection & Usage

### Essential Tools
- [ ] **Disassemblers**: Ghidra, IDA Pro, Radare2, Binary Ninja
- [ ] **Debuggers**: GDB (with pwndbg/GEF/peda), x32dbg/x64dbg
- [ ] **Exploitation Frameworks**: pwntools, ROPgadget, ropper
- [ ] **Binary Analysis**: checksec, objdump, readelf, nm
- [ ] **Hex Editors**: hexdump, xxd, bless

### Specialized Tools
- [ ] **one_gadget** - Find one-shot execve gadgets
- [ ] **libc-database** - Identify libc version from leaked addresses
- [ ] **seccomp-tools** - Analyze seccomp filters
- [ ] **Angr** - Binary analysis platform for complex analysis

## 🚀 Payload Development

### Shellcode Considerations
- [ ] Determine allowed characters (alphanumeric, printable, etc.)
- [ ] Choose appropriate shellcode type (execve, connect-back, etc.)
- [ ] Handle bad characters and encoding if necessary
- [ ] Test shellcode in isolated environment

### ROP Chain Construction
- [ ] Find necessary gadgets (`pop rdi; ret`, `pop rsi; ret`, etc.)
- [ ] Chain gadgets to set up system call or function call
- [ ] Handle stack alignment requirements
- [ ] Test ROP chain reliability

### Exploit Delivery
- [ ] Choose delivery method (network, file input, command line)
- [ ] Handle input parsing and format requirements
- [ ] Account for timing issues or race conditions
- [ ] Test exploit reliability and success rate

## 🔄 Common Pitfalls & Debugging

### Troubleshooting Checklist
- [ ] **Stack Alignment** - Ensure 16-byte alignment for x64
- [ ] **Null Bytes** - Avoid null terminators in strings
- [ ] **Bad Characters** - Filter out characters that break input parsing
- [ ] **Buffer Sizes** - Ensure payload fits in available space
- [ ] **Address Calculation** - Double-check offset calculations
- [ ] **Endianness** - Pack addresses in correct byte order

### Testing & Validation
- [ ] Test exploit locally first
- [ ] Verify exploit works against target environment
- [ ] Check for remote vs local differences
- [ ] Test exploit reliability (success rate > 90%)
- [ ] Ensure clean exit or stable post-exploitation state

## 🎯 Final Exploitation

### Pre-Flight Check
- [ ] Confirm target environment matches local setup
- [ ] Verify all addresses and offsets are correct
- [ ] Test payload delivery mechanism
- [ ] Prepare backup exploitation strategies

### Execution
- [ ] Run exploit and capture flag
- [ ] Document successful exploitation method
- [ ] Clean up any artifacts or processes
- [ ] Verify flag format and submission requirements

## 📚 Learning Resources

### Essential Reading
- [ ] "The Shellcoder's Handbook" - Buffer overflow techniques
- [ ] "Hacking: The Art of Exploitation" - Fundamental concepts
- [ ] "A Guide to Kernel Exploitation" - Advanced techniques
- [ ] Various CTF writeups and tutorials

### Practice Platforms
- [ ] **pwn.college** - Systematic binary exploitation learning
- [ ] **OverTheWire** - Wargames including binary challenges
- [ ] **picoCTF** - Beginner-friendly challenges
- [ ] **CTFtime** - Track ongoing CTF competitions

---

## ⚡ Quick Reference Commands

```bash
# File analysis
file binary
checksec binary
strings binary
objdump -d binary

# GDB debugging
gdb ./binary
r < payload
info registers
x/20x $rsp

# pwntools template
from pwn import *
p = process('./binary')
# or p = remote('host', port)
payload = b'A' * offset + p64(address)
p.sendline(payload)
```

Remember: Each CTF challenge is unique. Use this checklist as a systematic approach, but be prepared to adapt your strategy based on the specific vulnerabilities and constraints you discover!