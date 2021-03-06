CXX = g++
CPPFLAGS = -Isrc. -Wall
CXXFLAGS = -Wall -Isrc -pedantic -std=gnu++11 -O2
# -Wno-unused-variable
LIBFLAGS =
# -Llib -l80over53
PROGRAMS = bin/80over53-server
INSTALL_PATH = /usr/local/bin

.PHONY: all install clean

all: bin $(PROGRAMS)

lib:
	mkdir lib

bin:
	mkdir bin

bin/80over53-server: src/server.o src/dns.o src/http.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBFLAGS)

install: $(PROGRAMS)
	install $(PROGRAMS) -m755 $(INSTALL_PATH)

clean:
	rm -rf bin
	rm -rf lib
	rm -f src/*.o
