
BUILDROOT_DIR=/home/marco/Desktop/buildroot-2022.02.3
KERNEL=$(BUILDROOT_DIR)/output/build/linux-5.15.18
CC = $(BUILDROOT_DIR)/output/host/bin/aarch64-linux-gcc
CFLAGS = -Wall -Wextra -g -static #-fsanitize=address

PROGRAMS := acipher aes hello_world hotp plugins random secure_storage
PROGRAMS := $(addprefix out/, $(PROGRAMS))

CFLAGS += -Iinclude/ 

.PHONY = all clean

all: $(PROGRAMS)

libteec/libteec.a:
	$(MAKE) -C libteec all

clean:
	rm -r out

out/%: %/main.c libteec/libteec.a
	mkdir -p out
	$(CC) $(CFLAGS) -I$(@:out/%=%)/include $< -o $@ libteec/libteec.a
