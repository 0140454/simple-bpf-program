CLANG = $(shell which clang)
LLC   = $(shell which llc)

ifeq "$(CLANG)" ""
    $(error Cannot find clang!)
endif

ifeq "$(LLC)" ""
    $(error Cannot find llc (llvm)!)
endif

.build/bpf.o: bpf.c
	@mkdir -p .build
	clang -O2 -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o .build/bpf.o

start: .build/bpf.o
ifeq "$(DEVICE)" ""
	$(error Please specify a device by `DEVICE` parameter!)
endif
	
	sudo tc qdisc add dev "$(DEVICE)" handle 1: root sfq
	sudo tc filter add dev "$(DEVICE)" parent 1: bpf obj .build/bpf.o flowid 1:1

	sudo tc qdisc add dev "$(DEVICE)" handle ffff: ingress
	sudo tc filter add dev "$(DEVICE)" parent ffff: protocol all u32 match u32 00000000 00000000 at 0 action bpf obj .build/bpf.o ok

stop: .build/bpf.o
ifeq "$(DEVICE)" ""
	$(error Please specify a device by `DEVICE` parameter!)
endif
	
	sudo tc filter del dev "$(DEVICE)" parent 1:
	sudo tc qdisc del dev "$(DEVICE)" handle 1: root

	sudo tc filter del dev "$(DEVICE)" ingress
	sudo tc qdisc del dev "$(DEVICE)" handle ffff: ingress

clean:
	rm -rf .build
