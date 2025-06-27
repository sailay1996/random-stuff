# 🛠️ Pwn CTF Binary Exploitation Checklist

A detailed and exhaustive checklist to approach CTF binary exploitation challenges methodically — reducing blind spots, maximizing insights, and ensuring surgical precision.

---

## 🔰 0. Setup and Environment
- [ ] Create isolated working directory for the challenge
- [ ] Copy binary, Dockerfile (if any), and challenge files
- [ ] Set up tools: `pwndbg`, `gef`, or `peda`
- [ ] Prepare debugger with `~/.gdbinit`, custom GEF configs
- [ ] Initialize script: `exploit.py` using `pwntools`

---

## 📦 1. Binary Reconnaissance
- [ ] Run `file chall`
- [ ] Run `checksec chall`
- [ ] Run `strings chall` to find format strings, debug info
- [ ] Run `readelf -a chall` and `objdump -d chall`
- [ ] Identify: Architecture, PIE, RELRO, Canary, NX, STRIPPED
- [ ] Determine: static vs dynamic binary (linked libs?)
- [ ] Identify function symbols (`nm`, `objdump`, Ghidra/IDA)

---

## 🔎 2. Dynamic Behavior Observation
- [ ] Run the binary manually and feed basic inputs
  - [ ] Alphabetic spam: `AAAA...`
  - [ ] Format string: `%x %x %x`, `%n`
  - [ ] Nulls, `\n`, special characters
- [ ] Check for usage of `scanf`, `gets`, `read`, `fgets`, etc.
- [ ] Identify crash with overflow patterns via `cyclic` pattern
- [ ] Run under debugger: `gdb ./chall` → `start`, `break main`

---

## 🧠 3. Reverse Engineering / Code Flow Analysis
- [ ] Load in Ghidra/IDA/Binary Ninja
- [ ] Understand main(), branches, input parsing, output
- [ ] Identify interesting functions, `system`, `execve`, or shell references
- [ ] Look for logic bugs: auth bypass, file access, bad assumptions

---

## 🔥 4. Vulnerability Identification

### Stack Overflow:
- [ ] Does buffer size allow `RIP` overwrite?
- [ ] `NX`? → Use ROP
- [ ] `Canary`? → Leak needed
- [ ] PIE? → Leak or bruteforce required

### Format String:
- [ ] `%x`, `%s`, `%n` responses confirm vuln
- [ ] Can you leak stack/PIE/libc/canary?
- [ ] Can you write arbitrary memory?
- [ ] GOT overwrite possible?

### Heap Bug:
- [ ] `malloc`, `free`, `calloc` → Check glibc version
- [ ] Double-free, UAF, overflow, off-by-one?
- [ ] Leak `libc` pointer via unsorted bin?
- [ ] Can you poison `tcache` or `fastbin`?

### Other Vulns:
- [ ] Command injection via `system`, backticks, etc.
- [ ] Integer overflow → allocation / copy bugs
- [ ] Logic bugs → auth, token bypass, function misuse

---

## 🔧 5. Exploit Plan Decision Tree

| Vuln Type        | Exploit Path                                    |
|------------------|-------------------------------------------------|
| Stack BOF + NX=off | Shellcode injection on stack                  |
| Stack BOF + NX=on  | ROP → leak libc → ret2libc or syscall chain  |
| Stack BOF + Canary | Leak → brute → stack pivot/ROP               |
| Format String     | Leak PIE/Canary/Libc → write primitive         |
| Format + NX       | GOT overwrite → system/one_gadget              |
| Heap Tcache dup   | Overwrite `__free_hook` / `__malloc_hook`     |
| UAF               | Reuse freed chunk for tcache poison            |
| Partial overwrite | GOT / return addr LSB for loop/win redirect   |

---

## 🧪 6. Exploit Development
- [ ] Build working payload for local
- [ ] Setup pwntools script with logic:
  - [ ] Leak stage (PIE, libc, canary)
  - [ ] Calculate addresses (base + offset)
  - [ ] Construct final ROP/shellcode payload
  - [ ] Interact with shell or get flag

---

## 🌐 7. Remote Extension (if applicable)
- [ ] Identify remote IP:PORT or socket interaction
- [ ] Handle menu parsing if interactive
- [ ] Implement timing/delay adjustments
- [ ] Strip unnecessary logging for speed
- [ ] Add bruteforce logic for PIE/Canary/LSB if needed

---

## 🧹 8. Final Checks and Cleanup
- [ ] Exploit script is readable and modular
- [ ] Add comments for each exploit stage
- [ ] Save crash logs, offset calculations
- [ ] Push final writeup + script to repo

---

## 🧠 Extra Tips
- [ ] Always check for `_start` and `_init` code logic
- [ ] Search `.init_array` for backdoored logic
- [ ] Validate `read`, `write`, and `fopen` file paths if relevant
- [ ] If stuck, check `seccomp`, `LD_PRELOAD`, sandboxing
- [ ] If there's `strace`/`ltrace`, use them for syscall behavior

---

## 📚 Recommended Tools
- `pwntools`, `ropper`, `ROPgadget`, `one_gadget`, `angr`
- `Ghidra`, `IDA Free`, `Binary Ninja`, `cutter`
- `gef`, `pwndbg`, `peda`
- `seccomp-tools`, `libheap`, `heaptrace`, `libc-database`

---

Happy pwning — may your shell always pop 🐚

---

_Contributions welcome. PRs encouraged._

