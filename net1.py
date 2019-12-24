from pwn import *

c = remote(args.HOST, int(args.PORT))
data = c.recv(4)

payload = u32(data)

c.sendline('%d' % payload)

ret = c.recvline()  # FIXME: this sometimes tracebacks for some reason
assert ret == 'you correctly sent the data\n'
