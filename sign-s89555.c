/*
 * Lamport One-Time Signature Scheme
 * Signature Generation
 * ==========================================================
 * This program reads a private key from a file, hashes an input file, and generates a signature based on the hash and the private key.
 * The signature is written to a file with the same name as the input file, but with a ".sign" extension.
 * The private key file must be readable only by the user, and the program checks the file permissions before reading.
 * The program uses OpenSSL for hashing and file operations.
 * 
 * USAGE:
 * Compile with: make sign-s89555
 * Run with: ./sign-s89555 <filename> 
 * or to capture output (enable DEBUG_MODE) and errors: ./sign-s89555 <filename> > output.txt 2> errors.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include "lamport.h"

int can_read_private_key(const char *file_name) {
    struct stat st;
    if (stat(file_name, &st) != 0) {
        fprintf(stderr, "Error: Cannot access private key file %s\n", file_name);
        return 0;
    }
    
    // Check if the file is readable by the user only
    if ((st.st_mode & S_IRUSR) && !(st.st_mode & (S_IRGRP | S_IROTH))) {
        return 1; 
    } else {
        fprintf(stderr, "Error: Private key file permissions are not secure\n");
        return 0; 
    }
}

int read_private_key(unsigned char private_key[NUM_BITS][2][KEY_SIZE]) {
    // Check if the private key file is readable
    if (!can_read_private_key(PRIV_FILE_NAME)) {
        fprintf(stderr, "Error: Cannot read private key file %s\n", PRIV_FILE_NAME);
        return 0;
    }
    FILE *priv_file = fopen(PRIV_FILE_NAME, "r");
    if (priv_file == NULL) {
        fprintf(stderr, "Error: Cannot open private key file %s\n", PRIV_FILE_NAME);
        return 0;
    }
    
    char line[KEY_SIZE * 2 + 2]; // 2 hex chars per byte + newline + null terminator
    int i, j, k;
    
    // Read private key: each line contains exactly 32 bytes (64 hex chars)
    for (i = 0; i < NUM_BITS; i++) {
        for (j = 0; j < 2; j++) {
            if (fgets(line, sizeof(line), priv_file) == NULL) { 
                fprintf(stderr, "Error: Invalid private key file format\n");
                fclose(priv_file);
                return 0;
            }
            
            // Convert hex string to bytes
            for (k = 0; k < KEY_SIZE; k++) {
                if (sscanf(line + k * 2, "%2hhx", &private_key[i][j][k]) != 1) { // hh for unsigned char, %2 for two hex digits, x for hex
                    fprintf(stderr, "Error: Invalid hex data in private key file\n");
                    fclose(priv_file);
                    return 0;
                }
            }
        }
    }
    
    fclose(priv_file);
    return 1;
}

// Optionally, read private key from binary file (not required)
int read_private_binary_key(unsigned char private_key[NUM_BITS][2][KEY_SIZE]) {
    // Check if the private key binary file is readable
    if (!can_read_private_key(PRIV_BINARY_FILE_NAME)) {
        fprintf(stderr, "Error: Cannot read private key binary file %s\n", PRIV_BINARY_FILE_NAME);
        return 0;
    }
    FILE *priv_file = fopen(PRIV_BINARY_FILE_NAME, "rb"); 
    if (priv_file == NULL) {
        fprintf(stderr, "Error: Cannot open private key binary file %s\n", PRIV_BINARY_FILE_NAME);
        return 0;
    }
    
    // Read private key from binary file
    if (fread(private_key, sizeof(unsigned char), NUM_BITS * 2 * KEY_SIZE, priv_file) != NUM_BITS * 2 * KEY_SIZE) {
        fprintf(stderr, "Error: Invalid private key binary file format\n");
        fclose(priv_file);
        return 0;
    }
    
    fclose(priv_file);
    return 1;
}

int hash_file(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return 0;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // create new hash context
    if (mdctx == NULL) {
        fprintf(stderr, "Error: Failed to create hash context\n");
        fclose(file);
        return 0;
    }
    
    // Initialize SHA-256 hash
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error: Failed to initialize hash\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }
    
    unsigned char buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) { // read file in chunks and store in buffer
        DEBUG_PRINT("Read %zu bytes from file\n", bytes_read);
        DEBUG_PRINT("File content:\n");
        for (size_t i = 0; i < bytes_read; i++) {
            DEBUG_PRINT("%c", buffer[i]); // print buffer content as characters
        }
        DEBUG_PRINT("\nFile content (hex):\n");
        for (size_t i = 0; i < bytes_read; i++) {
            DEBUG_PRINT("%02x", buffer[i]); // print buffer content in hex
        }
        // Update hash with buffer data
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) { 
            fprintf(stderr, "Error: Failed to update hash\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 0;
        }
    }
    
    unsigned int hash_len;
    // Finalize hash and store in output hash
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "Error: Failed to finalize hash\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }
    DEBUG_PRINT("\nFinal hash (hex):\n");
    for (size_t i = 0; i < hash_len; i++) {
        DEBUG_PRINT("%02x", hash[i]); // print final hash in hex
    }
    DEBUG_PRINT("\n");
    
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 1;
}

int create_signature(const char *sig_filename, unsigned char private_key[NUM_BITS][2][KEY_SIZE], const unsigned char *hash) {
    FILE *sig_file = fopen(sig_filename, "w");
    if (sig_file == NULL) {
        fprintf(stderr, "Error: Cannot create signature file %s\n", sig_filename);
        return 0;
    }
    
    // For each bit in the hash, write the corresponding private key component
    int i, j, k;
    for (i = 0; i < HASH_SIZE; i++) { // for each byte in the hash
        for (j = 0; j < 8; j++) { // for each bit in the byte
            // Determine which private key component to use based on the bit value
            int bit_index = i * 8 + j;
            int bit_value = (hash[i] >> (7 - j)) & 1; // Right-shifts to move the desired bit to position 0 and masks it
            DEBUG_PRINT("Hash byte %d: %02x\n", i, hash[i]);
            DEBUG_PRINT("Using private key[%d][%d]\n", bit_index, bit_value);

            // Write the selected private key component as hex (32 bytes per line + newline)
            for (k = 0; k < KEY_SIZE; k++) {
                fprintf(sig_file, "%02x", private_key[bit_index][bit_value][k]);
                DEBUG_PRINT("Signature[%d][%d][%d]: %02x\n", bit_index, bit_value, k, private_key[bit_index][bit_value][k]);
            }
            fprintf(sig_file, "\n");
        }
    }
    fclose(sig_file);
    return 1;
}

int create_binary_signature(const char *sig_filename, unsigned char private_key[NUM_BITS][2][KEY_SIZE], const unsigned char *hash) {
    // Create binary signature file
    FILE *sig_file = fopen(sig_filename, "wb");
    if (sig_file == NULL) {
        fprintf(stderr, "Error: Cannot create binary signature file %s\n", sig_filename);
        return 0;
    }
    // For each bit in the hash, write the corresponding private key component
    int i, j;
    for (i = 0; i < HASH_SIZE; i++) { // for each byte in the hash
        for (j = 0; j < 8; j++) { // for each bit in the byte
            // Determine which private key component to use based on the bit value
            int bit_index = i * 8 + j;
            int bit_value = (hash[i] >> (7 - j)) & 1; // Right-shifts to move the desired bit to position 0 and masks it
            DEBUG_PRINT("Hash byte %d: %02x\n", i, hash[i]);
            DEBUG_PRINT("Using private key[%d][%d]\n", bit_index, bit_value);

            // Write the selected private key component as binary data
            if (fwrite(private_key[bit_index][bit_value], sizeof(unsigned char), KEY_SIZE, sig_file) != KEY_SIZE) {
                fprintf(stderr, "Error: Failed to write binary signature data\n");
                fclose(sig_file);
                return 0;
            }
            DEBUG_PRINT("Wrote signature[%d][%d] to binary file\n", bit_index, bit_value);
        }
    }
    fclose(sig_file);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename> [-b]\n", argv[0]);
        fprintf(stderr, "       -b: create binary signature file\n");
        return 1;
    }
    
    const char *filename = argv[1];
    unsigned char private_key[NUM_BITS][2][KEY_SIZE];
    unsigned char hash[HASH_SIZE];
    
    // Read private key
    if (!read_private_key(private_key)) {
        return 1;
    }
    
    // Hash the input file
    if (!hash_file(filename, hash)) {
        return 1;
    }
    
    // Create signature filename
    char sig_filename[strlen(filename) + strlen(SIGN_EXTENSION) + 1];
    sprintf(sig_filename, "%s%s", filename, SIGN_EXTENSION);
    
    // Create signature
    if (!create_signature(sig_filename, private_key, hash)) {
        return 1;
    }

    printf("Signature successfully created for file: %s\n", filename);
    printf("Signature file: %s\n", sig_filename);
   
    // Optionally, check if -b option is provided for binary signature (not required)
    if (argc > 2 && strcmp(argv[2], "-b") == 0) {
        unsigned char private_binary_key[NUM_BITS][2][KEY_SIZE];
        if (!read_private_binary_key(private_binary_key)) {
            return 1;
        }
        char sig_binary_filename[strlen(filename) + strlen(SIGN_BINARY_EXTENSION) + 1];
        sprintf(sig_binary_filename, "%s%s", filename, SIGN_BINARY_EXTENSION);
        if (!create_binary_signature(sig_binary_filename, private_binary_key, hash)) {
            return 1;
        }
        printf("Binary signature file: %s\n", sig_binary_filename);
    }
    return 0;
}