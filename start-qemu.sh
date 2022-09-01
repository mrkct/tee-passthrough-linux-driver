#!/bin/bash

QEMU_BIN="/home/marco/Desktop/tee-passthrough/build/qemu-system-aarch64"

$QEMU_BIN \
	-M virt \
	-cpu cortex-a53 \
	-nographic \
	-smp 1 \
	-kernel vm/Image \
	-append "rootwait root=/dev/vda console=ttyAMA0" \
	-netdev user,id=eth0 -device virtio-net-device,netdev=eth0 \
	-drive file=vm/rootfs.ext2,if=none,format=raw,id=hd0 \
	-device virtio-blk-device,drive=hd0 \
	$EXTRA_ARGS
