/*
 * Lamport One-Time Signature Scheme
 * Signature Verification
 * ==========================================================
 * This program verifies a Lamport one-time signature by reading the public key, signature, and the hash of the input file.
 * It checks if the signature is valid against the public key and the hash.
 *
 * USAGE:
 * Compile with: make verify-s89555
 * Run with: ./verify-s89555 <filename> [-b]
 * Run with capture output (enable DEBUG_MODE) and errors: ./verify-s89555 <filename> [-b] > output.txt 2> errors.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "lamport_common.h"

int read_signature(const char *sig_filename, unsigned char signature[NUM_BITS][KEY_SIZE]);
int verify_signature(unsigned char public_key[NUM_BITS][2][KEY_SIZE],
                     unsigned char signature[NUM_BITS][KEY_SIZE],
                     unsigned char *hash);

int main(int argc, char *argv[])
{
    if (argc != 2 && argc != 3)
    {
        fprintf(stderr, "Usage: %s <filename> [-b]\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    unsigned char public_key[NUM_BITS][2][KEY_SIZE];
    unsigned char signature[NUM_BITS][KEY_SIZE];
    unsigned char hash[HASH_SIZE];

    // Create signature filename
    char sig_filename[strlen(filename) + strlen(SIGN_EXTENSION) + 1];
    sprintf(sig_filename, "%s%s", filename, SIGN_EXTENSION);

    // Read public key
    if (!read_key(PUB_FILE_NAME, public_key))
    {
        return 1;
    }

    // Read signature
    if (!read_signature(sig_filename, signature))
    {
        return 1;
    }

    // Hash the input file
    if (!hash_file(filename, hash))
    {
        return 1;
    }

    // Optionally, check if -b option is provided for binary verification
    if (argc == 3 && strcmp(argv[2], "-b") == 0)
    {
        unsigned char public_binary_key[NUM_BITS][2][KEY_SIZE];
        if (!read_binary_key(PUB_BINARY_FILE_NAME, public_binary_key))
        {
            return 1;
        }
        // Verify binary signature
        if (verify_signature(public_binary_key, signature, hash))
        {
            printf("VALID (binary)\n");
            return 0;
        }
        else
        {
            printf("INVALID (binary)\n");
            return 1;
        }
    }
    else
    {
        // Verify signature
        if (verify_signature(public_key, signature, hash))
        {
            printf("VALID\n");
            return 0;
        }
        else
        {
            printf("INVALID\n");
            return 1;
        }
    }
}

int read_signature(const char *sig_filename, unsigned char signature[NUM_BITS][KEY_SIZE])
{
    FILE *sig_file = fopen(sig_filename, "r");
    if (sig_file == NULL)
    {
        fprintf(stderr, "Error: Cannot open signature file %s\n", sig_filename);
        return 0;
    }

    char line[KEY_SIZE * 2 + 2]; // 2 hex chars per byte + newline + null terminator
    int i, k;

    // Read signature: each line contains exactly 32 bytes (64 hex chars)
    for (i = 0; i < NUM_BITS; i++)
    {
        if (fgets(line, sizeof(line), sig_file) == NULL)
        {
            fprintf(stderr, "Error: Invalid signature file format\n");
            fclose(sig_file);
            return 0;
        }

        // Convert hex string to bytes
        for (k = 0; k < KEY_SIZE; k++)
        {
            if (sscanf(line + k * 2, "%2hhx", &signature[i][k]) != 1)
            {
                fprintf(stderr, "Error: Invalid hex data in signature file\n");
                fclose(sig_file);
                return 0;
            }
        }
    }

    fclose(sig_file);
    return 1;
}

int verify_signature(unsigned char public_key[NUM_BITS][2][KEY_SIZE],
                     unsigned char signature[NUM_BITS][KEY_SIZE],
                     unsigned char *hash)
{
    int i, j;
    unsigned char computed_hash[KEY_SIZE];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL)
    {
        fprintf(stderr, "Error: Failed to create hash context\n");
        return 0;
    }

    // For each bit in the hash, verify the signature component
    for (i = 0; i < HASH_SIZE; i++)
    {
        for (j = 0; j < 8; j++)
        {
            int bit_index = i * 8 + j;
            int bit_value = (hash[i] >> (7 - j)) & 1;

            // Hash the signature component
            if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
            {
                fprintf(stderr, "Error: Failed to initialize hash\n");
                EVP_MD_CTX_free(mdctx);
                return 0;
            }

            if (EVP_DigestUpdate(mdctx, signature[bit_index], KEY_SIZE) != 1)
            {
                fprintf(stderr, "Error: Failed to update hash\n");
                EVP_MD_CTX_free(mdctx);
                return 0;
            }

            unsigned int hash_len;
            if (EVP_DigestFinal_ex(mdctx, computed_hash, &hash_len) != 1)
            {
                fprintf(stderr, "Error: Failed to finalize hash\n");
                EVP_MD_CTX_free(mdctx);
                return 0;
            }
            DEBUG_PRINT("Hash byte %d: %02x, using public key[%d][%d]\n", i, computed_hash[i], bit_index, bit_value);

            // Compare with the corresponding public key component
            if (memcmp(computed_hash, public_key[bit_index][bit_value], KEY_SIZE) != 0)
            {
                EVP_MD_CTX_free(mdctx);
                return 0; // Verification failed
            }
        }
    }

    EVP_MD_CTX_free(mdctx);
    return 1; // Verification successful
}
