CFLAGS = -g -Wall -D_GNU_SOURCE -std=gnu11 -I$(HOME)/devel/include
LDFLAGS = -g -L$(HOME)/devel/lib
LIBS = -lmiscs -lmariadb

.PHONY: all clean

all: fmon lecho dirnot plidm rmtexe chpass

fmon: lease_mon.o file_monitor.o lease_parse.o
	$(LINK.o) $^ -o $@

lecho: CFLAGS += -pthread
lecho: LDFLAGS += -pthread
lecho: echo_lease.o dbproc.o dbconnect.o pipe_execution.o random_passwd.o
	$(LINK.o) $^ $(LIBS) -o $@

rmtexe: rmtexe.o pipe_execution.o
	$(LINK.o) $^ -lmiscs -o $@

chpass: chpass.o random_passwd.o dbconnect.o pipe_execution.o
	$(LINK.o) $^ $(LIBS) -o $@

dirnot:	inotify_dir.o
	$(LINK.o) $^ -o $@

plidm: ping_lidm.o
	$(LINK.o) $^ -o $@

release: plidm lecho

release: CFLAGS += -O2
release: LDFLAGS += -O1

clean:
	rm -f *.o *.d
	rm -f fmon lecho dirnot rmtexe plidm chpass

include $(HOME)/devel/lib/header-dep.mak
