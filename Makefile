CC = gcc
CCFLAGS = -Wall
CFLAGS = -Wall -I. -pedantic -std=gnu11 -Wno-unused-variable
LIBFLAGS =
PROGRAMS = 80over53-server
INSTALL_PATH = /usr/local/bin

.PHONY: all install clean

all: $(PROGRAMS)

80over53-server: 80over53-server.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBFLAGS)

install: $(PROGRAMS)
	install $(PROGRAMS) -m755 $(INSTALL_PATH)

clean:
	rm -f *.o *~ $(PROGRAMS)
