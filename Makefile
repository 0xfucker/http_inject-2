#!/usr/bin/make -f
CFLAGS=-g -Wall $(shell pcap-config --cflags)
LDFLAGS=
LDLIBS=$(shell pcap-config --libs) -lpthread
TARGET=http_inject

all: $(TARGET)

$(TARGET): main.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
