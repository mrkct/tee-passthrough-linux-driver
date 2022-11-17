
BUILDROOT_DIR=/home/marco/Desktop/buildroot-2022.02.3
KERNEL=$(BUILDROOT_DIR)/output/build/linux-5.15.18
CC = $(BUILDROOT_DIR)/output/host/bin/aarch64-linux-gcc
CFLAGS = -Wall -Wextra -g -static #-fsanitize=address

SOURCES = $(wildcard *.c)
PROGRAMS = $(SOURCES:.c=)

.PHONY = all clean

all: $(PROGRAMS)

clean:
	rm -f $(PROGRAMS)

libteec/libteec.a: 
	$(MAKE) -C libteec all

%: %.c libteec/libteec.a
	$(CC) $(CFLAGS) $< -o $@ libteec/libteec.a
