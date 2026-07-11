# BBRv3 out-of-tree kernel module Makefile
# Build with: make -C /path/to/kernel/source M=$(pwd) modules

obj-$(CONFIG_TCP_CONG_BBRV3) := tcp_bbrv3.o

# For standalone build without Kconfig integration:
obj-m := tcp_bbrv3.o

# Include the kernel's net/ipv4 directory for tcp_dctcp.h
ccflags-y += -I$(srctree)/net/ipv4
