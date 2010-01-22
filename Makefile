POLARPATH = /opt
CC = diet cc
CFLAGS = -std=gnu89 -pedantic -Wall -O2 -I$(POLARPATH)/include/
LDFLAGS = -s

all: smtp
.c.o:
	$(CC) -c $(CFLAGS) $<
smtp.o: config.h
smtp: smtp.o $(POLARPATH)/lib*/libpolarssl.a
	$(CC) $(LDFLAGS) -o $@ $^
clean:
	rm -f *.o smtp
ctags:
	ctags *.[hc]
