#!/bin/sh
set -e

DISK=vm/rootfs.ext2

mkdir -p MountPoint
mount $DISK MountPoint
rm -rf MountPoint/root/src
rm -rf MountPoint/root/tests
cp -r src/ MountPoint/root/src
cp -r tests MountPoint/root/tests

umount MountPoint

