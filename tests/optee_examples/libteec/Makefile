
BUILDROOT_DIR=/home/marco/Desktop/buildroot-2022.02.3
KERNEL=$(BUILDROOT_DIR)/output/build/linux-5.15.18
CC = $(BUILDROOT_DIR)/output/host/bin/aarch64-linux-gcc
AR = $(BUILDROOT_DIR)/output/host/bin/aarch64-linux-ar
CFLAGS = -Wall -Wextra -g -static -I./include -DBINARY_PREFIX=\"TEEC\" #-fsanitize=address

OBJECTS = src/tee_client_api.o src/teec_trace.o

.PHONY = all clean

all: libteec.a

libteec.a: $(OBJECTS)
	$(AR) -rcs libteec.a $(OBJECTS) 

%: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS)
	rm -f libteec.a