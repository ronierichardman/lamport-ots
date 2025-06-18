#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include "lamport.h"

int write_hex_file(const char *filename, unsigned char data[NUM_BITS][2][KEY_SIZE]) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create hex file %s\n", filename);
        return 0;
    }
    // Set file permissions to 600 (read/write for owner only)
    if (chmod(filename, S_IRUSR | S_IWUSR) != 0) {
        fprintf(stderr, "Warning: Could not set secure permissions on private key file\n");
    }
    // Write each byte as two hex characters
    for (int i = 0; i < NUM_BITS; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < KEY_SIZE; k++) {
                fprintf(file, "%02x", data[i][j][k]);
            }
            fprintf(file, "\n");
        }
    }
    fclose(file);
    return 1;
}

// not required, only for understanding purpose
int write_binary_file(const char *filename, unsigned char data[NUM_BITS][2][KEY_SIZE]) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create binary file %s\n", filename);
        return 0;
    }
    // Set file permissions to 600 (read/write for owner only)
    if (chmod(filename, S_IRUSR | S_IWUSR) != 0) {
        fprintf(stderr, "Warning: Could not set secure permissions on private key file\n");
    }
    // Write each key component as binary data
    for (int i = 0; i < NUM_BITS; i++) {
        for (int j = 0; j < 2; j++) {
            if (fwrite(data[i][j], sizeof(unsigned char), KEY_SIZE, file) != KEY_SIZE) {
                fprintf(stderr, "Error: Failed to write binary data to file %s\n", filename);
                fclose(file);
                return 0;
            }
        }
    }
    fclose(file);
    return 1;
}

int main(int argc, char *argv[]) {
    unsigned char private_key[NUM_BITS][2][KEY_SIZE];
    unsigned char public_key[NUM_BITS][2][KEY_SIZE];
    int i, j;
    
    // checks whether the random number generator has been sufficiently seeded with entropy
    // Entropy is randomness from unpredictable sources like: Mouse movements, Keyboard timings etc.
    if (!RAND_status()) {
        fprintf(stderr, "Error: Not enough entropy for random number generation\n");
        return 1;
    }
    
    // Generate private key (random values)
    for (i = 0; i < NUM_BITS; i++) {
        for (j = 0; j < 2; j++) {
            if (RAND_priv_bytes(private_key[i][j], KEY_SIZE) != 1) {
                fprintf(stderr, "Error: Failed to generate random bytes\n");
                return 1;
            }
        }
    }
    
    // Generate public key (hash of private key components)
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // Create new hash context
    if (mdctx == NULL) {
        fprintf(stderr, "Error: Failed to create hash context\n");
        return 1;
    }
    
    for (i = 0; i < NUM_BITS; i++) {
        for (j = 0; j < 2; j++) {
            // Initialize SHA-256 hash
            if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) { 
                fprintf(stderr, "Error: Failed to initialize hash\n");
                EVP_MD_CTX_free(mdctx); // Free hash context
                return 1;
            }
            
            // Update hash with private key 
            if (EVP_DigestUpdate(mdctx, private_key[i][j], KEY_SIZE) != 1) { 
                fprintf(stderr, "Error: Failed to update hash\n");
                EVP_MD_CTX_free(mdctx);
                return 1;
            }
            
            unsigned int hash_len;
            // Finalize hash and store in public key
            if (EVP_DigestFinal_ex(mdctx, public_key[i][j], &hash_len) != 1) {
                fprintf(stderr, "Error: Failed to finalize hash\n");
                EVP_MD_CTX_free(mdctx);
                return 1;
            }
        }
    }
    
    EVP_MD_CTX_free(mdctx);

    // Write private key to hex file
    if (!write_hex_file(PRIV_FILE_NAME, private_key)) {
        return 1;
    }
    // Write public key to hex file
    if (!write_hex_file(PUB_FILE_NAME, public_key)) {
        return 1;
    }
    
    // // Write private key to file
    // priv_file = fopen(PRIV_FILE_NAME, "w");
    // if (priv_file == NULL) {
    //     fprintf(stderr, "Error: Cannot create private key file\n");
    //     return 1;
    // }
    
    // // Set file permissions to 600 (read/write for owner only)
    // if (chmod(PRIV_FILE_NAME, S_IRUSR | S_IWUSR) != 0) {
    //     fprintf(stderr, "Warning: Could not set secure permissions on private key file\n");
    // }
    
    // // Write private key: each line contains exactly 32 bytes (64 hex chars) + newline
    // for (i = 0; i < NUM_BITS; i++) {
    //     for (j = 0; j < 2; j++) {
    //         for (k = 0; k < KEY_SIZE; k++) {
    //             fprintf(priv_file, "%02x", private_key[i][j][k]);
    //         }
    //         fprintf(priv_file, "\n");
    //     }
    // }
    // fclose(priv_file);
    
    // // Write public key to file
    // pub_file = fopen(PUB_FILE_NAME, "w");
    // if (pub_file == NULL) {
    //     fprintf(stderr, "Error: Cannot create public key file\n");
    //     return 1;
    // }

    
    // // Write public key: each line contains exactly 32 bytes (64 hex chars) + newline
    // for (i = 0; i < NUM_BITS; i++) {
    //     for (j = 0; j < 2; j++) {
    //         for (k = 0; k < KEY_SIZE; k++) {
    //             fprintf(pub_file, "%02x", public_key[i][j][k]);
    //         }
    //         fprintf(pub_file, "\n");
    //     }
    // }
    // fclose(pub_file);

    // // Write private key to binary file 
    // FILE *priv_binary_file = fopen(PRIV_BINARY_FILE_NAME, "wb");
    // if (priv_binary_file == NULL) {
    //     fprintf(stderr, "Error: Cannot create private key binary file\n");
    //     return 1;
    // }
    // for (i = 0; i < NUM_BITS; i++) {
    //     for (j = 0; j < 2; j++) {
    //         fwrite(private_key[i][j], 1, KEY_SIZE, priv_binary_file);
    //     }
    // }
    // fclose(priv_binary_file);

    // // Write public key to binary file 
    // FILE *pub_binary_file = fopen(PUB_BINARY_FILE_NAME, "wb");
    // if (pub_binary_file == NULL) {
    //     fprintf(stderr, "Error: Cannot create public key binary file\n");
    //     return 1;
    // }
    // for (i = 0; i < NUM_BITS; i++) {
    //     for (j = 0; j < 2; j++) {
    //         fwrite(public_key[i][j], 1, KEY_SIZE, pub_binary_file);
    //     }
    // }
    // fclose(pub_binary_file);

    printf("Lamport one-time signature key pair generated successfully.\n");
    printf("Private key: %s\n", PRIV_FILE_NAME);
    printf("Public key: %s\n", PUB_FILE_NAME);

    // Optionally, if the -b option is provided, write binary files (not required)
    if (argc > 1 && strcmp(argv[1], "-b") == 0) {
        // Write private key to binary file
        if (!write_binary_file(PRIV_BINARY_FILE_NAME, private_key)) {
            return 1;
        }
        // Write public key to binary file
        if (!write_binary_file(PUB_BINARY_FILE_NAME, public_key)) {
            return 1;
        }
        printf("Binary files created: %s and %s\n", PRIV_BINARY_FILE_NAME, PUB_BINARY_FILE_NAME);
    }

    return 0;
}
