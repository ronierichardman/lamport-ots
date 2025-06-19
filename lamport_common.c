#include "lamport_common.h"

int can_read_file(const char *file_name) {
    struct stat st;
    if (stat(file_name, &st) != 0) {
        fprintf(stderr, "Error: Cannot access file %s\n", file_name);
        return 0;
    }
    // Check if the file is readable by the user only
    if ((st.st_mode & S_IRUSR) && !(st.st_mode & (S_IRGRP | S_IROTH))) {
        return 1; 
    } else {
        fprintf(stderr, "Error: File permissions are not secure\n");
        return 0;
    }
}

int read_key(const char *file_name, unsigned char key[NUM_BITS][2][KEY_SIZE]) {
    FILE *file = fopen(file_name, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open key file %s\n", file_name);
        return 0;
    }
    
    char line[KEY_SIZE * 2 + 2]; // 2 hex chars per byte + newline + null terminator
    int i, j, k;
    
    // Read key: each line contains exactly 32 bytes (64 hex chars)
    for (i = 0; i < NUM_BITS; i++) {
        for (j = 0; j < 2; j++) {
            if (fgets(line, sizeof(line), file) == NULL) { 
                fprintf(stderr, "Error: Invalid key file format\n");
                fclose(file);
                return 0;
            }
            
            // Convert hex string to bytes
            for (k = 0; k < KEY_SIZE; k++) {
                if (sscanf(line + k * 2, "%2hhx", &key[i][j][k]) != 1) { // hh for unsigned char, %2 for two hex digits, x for hex
                    fprintf(stderr, "Error: Invalid hex data in key file\n");
                    fclose(file);
                    return 0;
                }
            }
        }
    }
    fclose(file);
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
        DEBUG_PRINT("File content (char):\n");
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

// Optionally, read key from binary file (not required)
int read_binary_key(const char *file_name, unsigned char key[NUM_BITS][2][KEY_SIZE])
{
    FILE *file = fopen(file_name, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Error: Cannot open key binary file %s\n", file_name);
        return 0;
    }
    // Read key from binary file
    if (fread(key, sizeof(unsigned char), NUM_BITS * 2 * KEY_SIZE, file) != NUM_BITS * 2 * KEY_SIZE)
    {
        fprintf(stderr, "Error: Invalid key binary file format\n");
        fclose(file);
        return 0;
    }
    fclose(file);
    return 1;
}