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

