CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -I. -I./openssl-3.5.0/include
LDFLAGS = -L./openssl-3.5.0 -lcrypto

TARGETS = keygen-s89555 sign-s89555 verify-s89555
COMMON_OBJ = lamport_common.o

all: $(TARGETS)

lamport_common.o: lamport_common.c lamport_common.h lamport_constants.h
	$(CC) $(CFLAGS) -c -o $@ $<

keygen-s89555: keygen-s89555.c lamport_constants.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sign-s89555: sign-s89555.c lamport_common.h $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(LDFLAGS)

verify-s89555: verify-s89555.c lamport_common.h $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON_OBJ) $(LDFLAGS)

clean:
	rm -f $(TARGETS) $(COMMON_OBJ) *.pub *.priv *.sign test*.txt *.jpg

test: all
	bash test.sh

.PHONY: all clean test
