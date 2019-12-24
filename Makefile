XNET = $(addprefix net,0 1 2 3)
XSTK = $(addprefix stack,0 1 2 3 4 5 6 7)

ALL = $(XNET) $(XSTK)

HOSTFWD_SSH  = hostfwd=tcp::10022-:22
HOSTFWD_NET0 = hostfwd=tcp::12999-:2999
HOSTFWD_NET1 = hostfwd=tcp::12998-:2998
HOSTFWD_NET2 = hostfwd=tcp::12997-:2997
HOSTFWD_NET3 = hostfwd=tcp::12996-:2996
HOSTFWD = $(HOSTFWD_SSH),$(HOSTFWD_NET0),$(HOSTFWD_NET1),$(HOSTFWD_NET2),$(HOSTFWD_NET3)

ISO = exploit-exercises-protostar-2.iso

all: $(ALL)

venv:
	virtualenv -p python2 $@
	(. venv/bin/activate $@ && pip install pwntools)

runvm: isocheck
	ssh-keygen -R "[localhost]:10022"
	qemu-system-x86_64 -enable-kvm -m 2G -nic user,$(HOSTFWD) -cdrom $(ISO)

isocheck: $(ISO)
	echo "46429afa18c472b0195b0378a5174a09bdc148e423919e7089c7b13ec23a1cf2 $(ISO)" | sha256sum -c

$(ISO):
	wget https://download.vulnhub.com/exploitexercises/$@ -O $@

$(ALL): HOST = localhost
$(ALL): USER = user
$(ALL): PASS = user
$(ALL): PORT = 10022
$(ALL): venv
	(. venv/bin/activate && python $@.py HOST=$(HOST) USER=$(USER) PASS=$(PASS) PORT=$(PORT) BIN=/opt/protostar/bin/$@)

net0: PORT = 12999
net1: PORT = 12998
net2: PORT = 12997
net3: PORT = 12996

.PHONY: runvm isocheck $(ALL)
