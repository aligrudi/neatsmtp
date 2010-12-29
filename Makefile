POLARPATH = /opt
CC = diet cc
CFLAGS = -Wall -O2 -I$(POLARPATH)/include/
LDFLAGS = -L$(POLARPATH)/lib -lpolarssl

all: smtp
.c.o:
	$(CC) -c $(CFLAGS) $<
smtp.o: config.h
smtp: smtp.o
	$(CC) -o $@ $^ $(LDFLAGS)
clean:
	rm -f *.o smtp
