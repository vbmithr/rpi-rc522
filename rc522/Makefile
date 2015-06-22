CFLAGS=-std=gnu11 -g -ggdb -D_GNU_SOURCE -Wall -Wno-unused-variable -Wno-unused-but-set-variable `pkg-config --cflags uuid` -Ideps/b64
LDFLAGS=-pthread `pkg-config --libs uuid` `pkg-config --libs sqlite3`
PROGS=main valet-rfidd

all: $(PROGS)

main: config.o rc522.o rfid.o deps/b64/encode.o deps/b64/decode.o

valet-rfidd: rc522.o rfid.o

.PHONY: clean deps

deps:
	clib install littlstar/b64.c

clean:
	rm -f *.o $(PROGS)
