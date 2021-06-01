CFLAGS = -g -Wall -Wpedantic
LDFLAGS = -g

.PHONY: all clean

all: fmon

fmon: lease_mon.o file_monitor.o lease_parse.o
	$(LINK.o) $^ -o $@

clean:
	rm -f *.o
	rm -f fmon
