export BUILDROOT_DIR=~/Desktop/buildroot-2022.02.3

export KDIR=$(BUILDROOT_DIR)/output/build/linux-5.15.18
export ARCH=arm64
export CROSS_COMPILE=$(BUILDROOT_DIR)/output/host/bin/aarch64-buildroot-linux-uclibc-

obj-m += driver.o

PWD := $(CURDIR)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
