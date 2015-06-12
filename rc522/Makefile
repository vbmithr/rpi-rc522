CFLAGS=-std=gnu11 -g -ggdb -D_GNU_SOURCE
PROGS=main

all: $(PROGS)

main: config.o rc522.o rfid.o

.PHONY: clean

clean:
	rm -f *.o $(PROGS)
