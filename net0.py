from pwn import *

c = remote(args.HOST, int(args.PORT))
c.recvuntil("Please send '")
n = int(c.recvuntil("'", drop=True))
c.recvline()

payload = p32(n)

c.send(payload)

ret = c.recvline()
assert ret == 'Thank you sir/madam\n'
