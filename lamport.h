#ifndef LAMPORT_H
#define LAMPORT_H

// Lamport One-Time Signature Constants
#define HASH_SIZE 32   // SHA-256 produces 32 bytes
#define KEY_SIZE 32    // 32 bytes per key component
#define NUM_BITS 256   // 256 bits in SHA-256 hash

// File names for key storage
#define PRIV_FILE_NAME "lamport-ots.priv"
#define PUB_FILE_NAME "lamport-ots.pub"
#define PRIV_BINARY_FILE_NAME "lamport-ots.bin.priv" // not required, only for understanding purpose
#define PUB_BINARY_FILE_NAME "lamport-ots.bin.pub" // not required, only for understanding purpose

// Signature file extension
#define SIGN_EXTENSION ".sign"
#define SIGN_BINARY_EXTENSION ".bin.sign" // not required, only for understanding purpose

// Debug mode control
#define DEBUG_MODE 1   // 1: enable debug output, 0: disable

// Debug macro for conditional printing
#if DEBUG_MODE
    #define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...) 
#endif

#endif
