# COMP6447 Wargame 1
Written by WENG XINN CHOW (z5346077) on 05.06.2022

intro
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS1pbnRybyIsImlwIjoiMTAzLjIxNi4xOTAuMzciLCJzZXNzaW9uIjoiZTRmMDMyM2ItZDY3ZS00NjZhLTgzYzQtYmEwMmZhOWQyMjc3In0.DREdyTGV1NAI6kKiM8cR90wRAgpn7moKKls13IoNgvo}

General overview of problems faced
-------------------------------------
1. Had to learn the basics of pwntools:  *remote*, *recvuntil*, *sendline*, *p16*, *u32*, etc.

2. Had to understand how computer stores bytes in little endian format.

3. Had to use disassembler (IDA) to break down the program into machine codes to find the secret hidden flag.

Script/Command used
------------------
```
from pwn import *

p = remote("comp6447.wtf",20478)

p.recvuntil('{')
res1 = int(p.recvuntil('}')[:-1], 16)
print(res1)
p.sendline(str(res1).encode('UTF-8'))

p.recvuntil('MINUS ')
minus = p.recvuntil('!')[:-1]
res2 = hex(res1 - int(minus, 16))
print(res2)
p.sendline(str(res2).encode('UTF-8'))

p.recvuntil('me ')
num = p.recvuntil('7')
res3 = p16(int(num, 16))
print(res3)
p.sendline(res3)

p.recvuntil('line)\n')
byte = p.recvuntil('\n')[:-1]
res4 = u32(byte)
print(res4)
p.sendline(str(res4).encode('UTF-8'))

res5 = hex(u32(byte))
print(res5)
p.sendline(str(res5).encode('UTF-8'))

res6 = 12835 + 12835
print(res6)
p.sendline(str(res6).encode('UTF-8'))

res7 = 'password'
p.sendline(res7)

p.interactive()
```
too-slow
=============
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS10b28tc2xvdyIsImlwIjoiMTAzLjIxNi4xOTAuMzciLCJzZXNzaW9uIjoiNjgyYWZhZGMtNjBjNC00MTc0LWEyNDEtODcyNjNhYTBiYWI5In0.0IVhLodaNFCQsqQ2bQ9__Rw_IzkdmaQ8vZ3uOGaT23Q}

General overview of problems faced
-------------------------------------
1. Nothing new from intro challenge except using a loop. 

2. I spent less time on this challenge after getting familiar to pwntools by doing the previous challenge. 

Script/Command used
------------------
```
from pwn import *

p = remote("comp6447.wtf",20677)

for t in range(0, 10):
    p.recvuntil('!\n')
    num1 = int((p.recvuntil('+')[:-1]).strip())
    # print(num1)
    p.recvuntil(' ')
    num2 = int(p.recvuntil('=')[:-1])
    # print(num2)
    res1 = num1 + num2
    print(res1)
    p.sendline(str(res1).encode('UTF-8'))

p.interactive()
```