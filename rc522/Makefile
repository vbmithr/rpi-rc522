CFLAGS=-std=gnu11 -g -ggdb -D_GNU_SOURCE -Wall -Wno-unused-variable -Wno-unused-but-set-variable `pkg-config --cflags uuid` -I/home/vb/code/openwrt/staging_dir/target-mips_34kc_musl-1.1.10/include -I/home/vb/code/openwrt/staging_dir/target-mips_34kc_musl-1.1.10/usr/include
LDFLAGS=-pthread `pkg-config --libs uuid` `pkg-config --libs sqlite3` -L/home/vb/code/openwrt/staging_dir/target-mips_34kc_musl-1.1.10/lib -L/home/vb/code/openwrt/staging_dir/target-mips_34kc_musl-1.1.10/usr/lib
PROGS=main valet-rfidd

all: $(PROGS)

main: config.o rc522.o rfid.o

valet-rfidd: rc522.o rfid.o

.PHONY: clean

clean:
	rm -f *.o $(PROGS)
