CFLAGS = -g -Wall -Wpedantic -I$(HOME)/devel/include
LDFLAGS = -g -L$(HOME)/devel/lib
LIBS = -lmiscs -lmariadb

.PHONY: all clean

all: fmon lecho dirnot plidm

fmon: lease_mon.o file_monitor.o lease_parse.o
	$(LINK.o) $^ -o $@

lecho: CFLAGS += -pthread
lecho: LDFLAGS += -pthread
lecho: echo_lease.o dbproc.o dbconnect.o
	$(LINK.o) $^ $(LIBS) -o $@

dirnot:	inotify_dir.o
	$(LINK.o) $^ -o $@

plidm: ping_lidm.o
	$(LINK.o) $^ -o $@

release: lecho

release: CFLAGS += -O2
release: LDFLAGS += -O1

clean:
	rm -f *.o *.d
	rm -f fmon lecho dirnot

include $(HOME)/devel/lib/header-dep.mak
