#!/bin/sh
set -e

DISK=vm/rootfs.ext2
DISK_INSIDE_VM=/home/marco/Desktop/op-tee/MountPoint/vm/rootfs.ext2
XTEST_ROOT=/home/marco/Desktop/xtest

mkdir -p MountPoint
mount $DISK MountPoint
rm -rf MountPoint/root/src
rm -rf MountPoint/root/tests

mkdir -p MountPoint/root/tests/optee_examples
cp -r src/ MountPoint/root/src
cp -r tests MountPoint/root/tests

cp -r tests/optee_examples/out/* MountPoint/root/tests/optee_examples
cp tests/S99-RunAllTests.sh MountPoint/etc/init.d/
cp -r $XTEST_ROOT MountPoint/root/tests/xtest

umount MountPoint
rm $DISK_INSIDE_VM
cp $DISK $DISK_INSIDE_VM
chown marco $DISK_INSIDE_VM
