CFLAGS=-std=gnu11 -g -ggdb -D_GNU_SOURCE -Wall -lsqlite3
PROGS=main valet-rfidd

all: $(PROGS)

main: config.o rc522.o rfid.o

valet-rfidd: rc522.o rfid.o

.PHONY: clean

clean:
	rm -f *.o $(PROGS)
