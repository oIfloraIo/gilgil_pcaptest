CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/include/pcap -I/usr/include/libnet
LDFLAGS = -lpcap -lnet

TARGET = pcap-test
SRCS = pcap-test.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean