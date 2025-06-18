CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -I. -I./openssl-3.5.0/include
LDFLAGS = -L./openssl-3.5.0 -lcrypto

TARGETS = keygen-s89555 sign-s89555 verify-s89555

all: $(TARGETS)

keygen-s89555: keygen-s89555.c lamport.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sign-s89555: sign-s89555.c lamport.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

verify-s89555: verify-s89555.c lamport.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.pub *.priv *.sign

test: all
	@echo "Testing key generation..."
	./keygen-s89555
	@echo "Creating test file..."
	echo "This is a test document for Lamport signature." > test.txt
	@echo "Testing signing..."
	./sign-s89555 test.txt
	@echo "Testing verification..."
	./verify-s89555 test.txt
	@echo "Testing with modified file..."
	echo "This is a modified test document." > test2.txt
	cp test.txt.sign test2.txt.sign
	./verify-s89555 test2.txt || echo "Expected: signature should be invalid"

.PHONY: all clean test
