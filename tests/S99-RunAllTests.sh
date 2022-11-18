#!/bin/sh

exit

BOLD_GREEN='\033[1;32m'
BOLD_RED='\033[1;31m' 
WHITE='\033[0;37m'

BASE=/root

insmod $BASE/src/driver.ko

echo -e $WHITE "--- TEE VERSION ---"
$BASE/tests/print_tee_version
if [ $? == 0 ]; then
    echo -e $BOLD_GREEN "--- PASSED ---";
else
    echo -e $BOLD_RED "--- CRASHED ---";
fi

echo -e $WHITE "--- SIMPLE CALL ---"
#$BASE/tests/test_simple_call
if [ $? == 0 ]; then
    echo -e $BOLD_GREEN "--- PASSED ---";
else
    echo -e $BOLD_RED "--- CRASHED ---";
fi

echo -e $WHITE "--- ALLOC SHARED MEMORY ---"
#$BASE/tests/test_alloc_shared_memory
if [ $? == 0 ]; then
    echo -e $BOLD_GREEN "--- PASSED ---";
else
    echo -e $BOLD_RED "--- CRASHED ---";
fi

echo -e $BOLD_RED "ALL TESTS COMPLETED"

# /sbin/poweroff -p