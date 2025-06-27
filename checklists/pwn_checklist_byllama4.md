# Binary Exploitation Checklist

## I. Preparation

* **Understand the binary**:
	+ Determine the architecture (x86, x64, ARM, etc.)
	+ Identify the operating system and libc version
	+ Check for security mitigations (PIE, RELRO, NX, etc.)
* **Set up your environment**:
	+ Choose a disassembler (Ghidra, IDA Pro, Radare2, etc.)
	+ Set up a debugger (GDB with pwndbg/GEF/peda, etc.)
	+ Familiarize yourself with exploitation frameworks (pwntools, etc.)

## II. Static Analysis

* **Disassemble the binary**:
	+ Identify the main function and program flow
	+ Map out all user-controlled input points
	+ Look for dangerous functions (strcpy, gets, scanf, etc.)
* **Identify vulnerabilities**:
	+ Buffer overflows
	+ Format string vulnerabilities
	+ Integer overflows
	+ Use-after-free vulnerabilities
	+ Double free vulnerabilities

## III. Dynamic Analysis

* **Debug the binary**:
	+ Set breakpoints at critical functions
	+ Analyze crash dumps and register states
	+ Determine controllable registers
* **Analyze memory layout**:
	+ Map memory regions (stack, heap, libraries, binary)
	+ Identify gadget locations for ROP chains
	+ Look for writable memory regions

## IV. Exploitation

* **Choose an exploitation technique**:
	+ Buffer overflow
	+ Return-to-libc
	+ ROP (Return-Oriented Programming)
	+ Format string exploitation
* **Craft a payload**:
	+ Determine the payload format (little-endian or big-endian)
	+ Choose a payload type (shellcode, ROP chain, etc.)
	+ Handle bad characters and encoding if necessary

## V. Post-Exploitation

* **Get a shell**:
	+ Use tools like pwntools to interact with the shell
	+ Stabilize the shell
* **Escalate privileges**:
	+ Identify potential vulnerabilities in the system or other processes
	+ Use these vulnerabilities to escalate privileges

## VI. Tools and Resources

* **Essential tools**:
	+ Disassemblers (Ghidra, IDA Pro, Radare2, etc.)
	+ Debuggers (GDB with pwndbg/GEF/peda, etc.)
	+ Exploitation frameworks (pwntools, etc.)
* **Additional resources**:
	+ Online tutorials and write-ups
	+ Books and research papers on binary exploitation