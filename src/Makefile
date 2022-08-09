export KDIR=../linux-5.15.18
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-

obj-m += driver.o

PWD := $(CURDIR)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
