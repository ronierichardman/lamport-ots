#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "lamport_constants.h"

int read_public_key(unsigned char public_key[NUM_BITS][2][KEY_SIZE]);
int read_signature(const char *sig_filename, unsigned char signature[NUM_BITS][KEY_SIZE]);
int hash_file(const char *filename, unsigned char *hash);
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
    if (!read_public_key(public_key))
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

int read_public_key(unsigned char public_key[NUM_BITS][2][KEY_SIZE])
{
    FILE *pub_file = fopen(PUB_FILE_NAME, "r");
    if (pub_file == NULL)
    {
        fprintf(stderr, "Error: Cannot open public key file %s\n", PUB_FILE_NAME);
        return 0;
    }

    char line[KEY_SIZE * 2 + 2]; // 2 hex chars per byte + newline + null terminator
    int i, j, k;

    // Read public key: each line contains exactly 32 bytes (64 hex chars)
    for (i = 0; i < NUM_BITS; i++)
    {
        for (j = 0; j < 2; j++)
        {
            if (fgets(line, sizeof(line), pub_file) == NULL)
            {
                fprintf(stderr, "Error: Invalid public key file format\n");
                fclose(pub_file);
                return 0;
            }

            // Convert hex string to bytes
            for (k = 0; k < KEY_SIZE; k++)
            {
                if (sscanf(line + k * 2, "%2hhx", &public_key[i][j][k]) != 1)
                {
                    fprintf(stderr, "Error: Invalid hex data in public key file\n");
                    fclose(pub_file);
                    return 0;
                }
            }
        }
    }

    fclose(pub_file);
    return 1;
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

int hash_file(const char *filename, unsigned char *hash)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return 0;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        fprintf(stderr, "Error: Failed to create hash context\n");
        fclose(file);
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    {
        fprintf(stderr, "Error: Failed to initialize hash\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    unsigned char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1)
        {
            fprintf(stderr, "Error: Failed to update hash\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 0;
        }
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
    {
        fprintf(stderr, "Error: Failed to finalize hash\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
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
