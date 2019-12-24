from pwn import *

c = remote(args.HOST, int(args.PORT))

payload = p32(sum(u32(c.recv(4)) for i in range(4)) & 0xffffffff)

c.send(payload)

ret = c.recvline()
assert ret == 'you added them correctly\n'
