CXX = g++
CPPFLAGS = -I. -Wall
CXXFLAGS = -Wall -I. -pedantic -std=gnu++11 -O2 -Wno-unused-variable
LIBFLAGS =
# -Llib -l80over53
PROGRAMS = 80over53-server
INSTALL_PATH = /usr/local/bin

.PHONY: all install clean

all: $(PROGRAMS)

80over53-server: 80over53-server.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBFLAGS)

install: $(PROGRAMS)
	install $(PROGRAMS) -m755 $(INSTALL_PATH)

clean:
	rm -f $(PROGRAMS)
	rm -f *.o
	rm -f *~
