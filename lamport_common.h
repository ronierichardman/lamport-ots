#ifndef LAMPORT_COMMON_H
#define LAMPORT_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include "lamport_constants.h"

int can_read_file(const char *file_name);
int read_key(const char *file_name, unsigned char key[NUM_BITS][2][KEY_SIZE]);
int read_binary_key(const char *file_name, unsigned char key[NUM_BITS][2][KEY_SIZE]);
int hash_file(const char *filename, unsigned char *hash);

#endif // LAMPORT_COMMON_H