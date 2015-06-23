CFLAGS=-std=gnu11 -g -ggdb -D_GNU_SOURCE -Wall -Wno-unused-variable -Wno-unused-but-set-variable `pkg-config --cflags uuid`
LDFLAGS=-pthread `pkg-config --libs uuid` `pkg-config --libs sqlite3`
PROGS=main

all: $(PROGS)

main: config.o rc522.o rfid.o base64.o

.PHONY: clean

clean:
	rm -f *.o $(PROGS)
