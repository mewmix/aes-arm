CC=gcc
CFLAGS=-fPIC -Wall -Wextra -O2

TARGET=libxts.so

SRCS=aes_armv8_xts.c aes_armv8_xts_asm.S
OBJS=$(SRCS:.c=.o)
OBJS:=$(OBJS:.S=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
