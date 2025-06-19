/*
 * Lamport One-Time Signature Scheme
 * Signature Generation
 * ==========================================================
 * This program reads a private key from a file, hashes an input file, and generates a signature based on the hash and the private key.
 * The signature is written to a file with the same name as the input file, but with a ".sign" extension.
 * The private key file must be readable only by the user, and the program checks the file permissions before reading.
 * The program uses OpenSSL for hashing and file operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lamport_common.h"

int create_signature(const char *sig_filename, unsigned char private_key[NUM_BITS][2][KEY_SIZE], const unsigned char *hash);
int create_binary_signature(const char *sig_filename, unsigned char private_key[NUM_BITS][2][KEY_SIZE], const unsigned char *hash);

int main(int argc, char *argv[])
{
    if (argc != 2 && argc != 3)
    {
        fprintf(stderr, "Usage: %s <filename> [-b]\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    unsigned char private_key[NUM_BITS][2][KEY_SIZE];
    unsigned char hash[HASH_SIZE];

    // Read private key
    if (!can_read_file(PRIV_FILE_NAME))
    {
        return 1;
    }
    if (!read_key(PRIV_FILE_NAME, private_key))
    {
        return 1;
    }

    // Hash the input file
    if (!hash_file(filename, hash))
    {
        return 1;
    }

    // Create signature filename
    char sig_filename[strlen(filename) + strlen(SIGN_EXTENSION) + 1];
    sprintf(sig_filename, "%s%s", filename, SIGN_EXTENSION);

    // Create signature
    if (!create_signature(sig_filename, private_key, hash))
    {
        return 1;
    }

    printf("Signature successfully created for file: %s\n", filename);
    printf("Signature file: %s\n", sig_filename);

    // Optionally, check if -b option is provided for binary signature (not required)
    if (argc == 3 && strcmp(argv[2], "-b") == 0)
    {
        unsigned char private_binary_key[NUM_BITS][2][KEY_SIZE];
        if (!can_read_file(PRIV_BINARY_FILE_NAME))
        {
            return 1;
        }
        if (!read_binary_key(PRIV_BINARY_FILE_NAME, private_binary_key))
        {
            return 1;
        }
        char sig_binary_filename[strlen(filename) + strlen(SIGN_BINARY_EXTENSION) + 1];
        sprintf(sig_binary_filename, "%s%s", filename, SIGN_BINARY_EXTENSION);
        if (!create_binary_signature(sig_binary_filename, private_binary_key, hash))
        {
            return 1;
        }
        printf("Binary signature successfully created for file: %s\n", filename);
        printf("Binary signature file: %s\n", sig_binary_filename);
    }
    return 0;
}

int create_signature(const char *sig_filename, unsigned char private_key[NUM_BITS][2][KEY_SIZE], const unsigned char *hash)
{
    FILE *sig_file = fopen(sig_filename, "w");
    if (sig_file == NULL)
    {
        fprintf(stderr, "Error: Cannot create signature file %s\n", sig_filename);
        return 0;
    }
    DEBUG_PRINT("\nCreating signature file: %s ...\n", sig_filename);
    int i, j, k;
    for (i = 0; i < HASH_SIZE; i++) // for each byte in the hash
    {
        for (j = 0; j < 8; j++) // for each bit in the byte
        {
            int bit_index = i * 8 + j;
            int bit_value = (hash[i] >> (7 - j)) & 1; // Right-shifts to move the desired bit to position 0 and masks it
            DEBUG_PRINT("Hash byte %d: %02x, using private key[%d][%d]\n", i, hash[i], bit_index, bit_value);

            // Write the selected private key component as hex (32 bytes per line + newline)
            for (k = 0; k < KEY_SIZE; k++)
            {
                fprintf(sig_file, "%02x", private_key[bit_index][bit_value][k]);
            }
            fprintf(sig_file, "\n");
        }
    }
    fclose(sig_file);
    return 1;
}

// Optionally, create binary signature file (not required)
int create_binary_signature(const char *sig_filename, unsigned char private_key[NUM_BITS][2][KEY_SIZE], const unsigned char *hash)
{
    // Create binary signature file
    FILE *sig_file = fopen(sig_filename, "wb");
    if (sig_file == NULL)
    {
        fprintf(stderr, "Error: Cannot create binary signature file %s\n", sig_filename);
        return 0;
    }
    DEBUG_PRINT("\nCreating binary signature file: %s ...\n", sig_filename);
    // For each bit in the hash, write the corresponding private key component
    int i, j;
    for (i = 0; i < HASH_SIZE; i++)
    { // for each byte in the hash
        for (j = 0; j < 8; j++)
        { // for each bit in the byte
            // Determine which private key component to use based on the bit value
            int bit_index = i * 8 + j;
            int bit_value = (hash[i] >> (7 - j)) & 1; // Right-shifts to move the desired bit to position 0 and masks it
            DEBUG_PRINT("Hash byte %d: %02x, using private key[%d][%d]\n", i, hash[i], bit_index, bit_value);

            // Write the selected private key component as binary data
            if (fwrite(private_key[bit_index][bit_value], sizeof(unsigned char), KEY_SIZE, sig_file) != KEY_SIZE)
            {
                fprintf(stderr, "Error: Failed to write binary signature data\n");
                fclose(sig_file);
                return 0;
            }
        }
    }
    fclose(sig_file);
    return 1;
}
