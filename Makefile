# common options
CC = cc

# for openssl
OBJS = smtp.o conn_openssl.o
CFLAGS = -Wall -O2
LDFLAGS = -lssl

# for mbedtls (polarssl)
#OBJS = smtp.o conn_mbedtls.o
#CFLAGS = -Wall -O2
#LDFLAGS = -lpolarssl

all: smtp
%.o: %.c conf.h
	$(CC) -c $(CFLAGS) $<
smtp: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	chmod 100 $@
clean:
	rm -f *.o smtp
