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
