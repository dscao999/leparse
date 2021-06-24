CFLAGS = -g -Wall -Wpedantic
LDFLAGS = -g

.PHONY: all clean

all: fmon lecho dirnot plidm

fmon: lease_mon.o file_monitor.o lease_parse.o
	$(LINK.o) $^ -o $@

lecho: echo_lease.o
	$(LINK.o) $^ -o $@

dirnot:	inotify_dir.o
	$(LINK.o) $^ -o $@

plidm: ping_lidm.o
	$(LINK.o) $^ -o $@

clean:
	rm -f *.o
	rm -f fmon lecho dirnot
