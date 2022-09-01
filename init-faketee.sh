#!/bin/sh

set -e

insmod /lib/modules/$(uname -r)/kernel/drivers/tee/tee.ko
insmod /home/marco/Desktop/fake-tee/src/faketee.ko
chown marco /dev/tee0
