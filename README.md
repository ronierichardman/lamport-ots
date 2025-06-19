# Lamport One-Time Signature Implementation

This implementation of the Lamport One-Time Signature scheme consists of three C programs for key pair generation, document signing, and signature verification.

## Prerequisites

- OpenSSL library (libcrypto) version 3.5.0
- GCC Compiler
- macOS/Linux/Unix environment

## Project Structure

```
lamport-ots/
├── keygen-s89555.c         # Key pair generation program
├── sign-s89555.c           # Document signing program  
├── verify-s89555.c         # Signature verification program
├── lamport_constants.h     # Constants and definitions
├── lamport_common.h        # Common function declarations
├── lamport_common.c        # Shared utility functions
├── Makefile               # Build configuration
├── test.sh                # Test script
├── README.md              # Main documentation
├── openssl-3.5.0/         # Local OpenSSL installation
└── ref/                   # Reference files for testing
    ├── document.jpg
    ├── document.jpg.sign
    ├── lamport-ots.pub
    └── test.txt
```

## Compilation

```bash
make all
```

Or individually:
```bash
make keygen-s89555
make sign-s89555
make verify-s89555
```

Manual compilation:
```bash
gcc -Wall -Wextra -std=c99 -g -I. -I./openssl-3.5.0/include -o keygen-s89555 keygen-s89555.c -L./openssl-3.5.0 -lcrypto
gcc -Wall -Wextra -std=c99 -g -I. -I./openssl-3.5.0/include -o sign-s89555 sign-s89555.c lamport_common.o -L./openssl-3.5.0 -lcrypto
gcc -Wall -Wextra -std=c99 -g -I. -I./openssl-3.5.0/include -o verify-s89555 verify-s89555.c lamport_common.o -L./openssl-3.5.0 -lcrypto
```

## Usage

### 1. Generate Key Pair

```bash
./keygen-s89555
```

Creates the files:
- `lamport-ots.pub` (public key, readable by all)
- `lamport-ots.priv` (private key, 600 permissions - owner only)

Optional binary format:
```bash
./keygen-s89555 -b
```

Additionally creates:
- `lamport-ots.bin.pub` (binary public key)
- `lamport-ots.bin.priv` (binary private key)

### 2. Sign Document

```bash
./sign-s89555 <filename>
```

Example:
```bash
./sign-s89555 document.txt
```

Creates the signature file `document.txt.sign`.

Optional binary signature:
```bash
./sign-s89555 document.txt -b
```

Additionally creates `document.txt.bin.sign` using binary keys.

### 3. Verify Signature

```bash
./verify-s89555 <filename>
```

Example:
```bash
./verify-s89555 document.txt
```

Output:
- `VALID` for valid signature (return code 0)
- `INVALID` for invalid signature (return code 1)

## How It Works

The Lamport One-Time Signature is based on:

1. **Key Generation**: For each bit of the SHA-256 hash (256 bits), two 32-byte random values are generated (private key). The public key consists of the SHA-256 hashes of these private key values.

2. **Signing**: The document is hashed with SHA-256. For each bit of the hash, the corresponding private key value is selected based on the bit value (0 or 1).

3. **Verification**: Each signature value is hashed and compared with the corresponding public key value to verify authenticity.

## Security Features

- **One-time use**: Each private key should only be used once
- **File permissions**: Private key files have restrictive permissions (600)
- **Secure random generation**: Uses `RAND_priv_bytes()` for cryptographically secure randomness
- **Binary-safe**: Works with any file type (text, images, executables, etc.)

## File Formats

- **Text format**: Hexadecimal representation (default)
- **Binary format**: Raw binary data (with `-b` option)
- Signature files use the same format as the keys used to create them

## Testing

```bash
make test
```

Or manually:
```bash
chmod +x test.sh
./test.sh
```

The test suite performs:
- Key generation testing
- Valid signature verification
- Invalid signature detection  
- Missing file error handling
- Reference signature verification

## Files

- `keygen-s89555.c` - Key pair generation
- `sign-s89555.c` - Signature creation
- `verify-s89555.c` - Signature verification
- `lamport_common.h` - Common header file
- `lamport_common.c` - Shared utility functions
- `lamport_constants.h` - Constants and definitions
- `Makefile` - Build configuration
- `test.sh` - Test script
- `README.md` - Main documentation

## Implementation Details

- **Hash Algorithm**: SHA-256 (256 bits = 256 key pairs)
- **Key Size**: 32 bytes per key component (KEY_SIZE)
- **File Formats**: Both hexadecimal text and binary formats supported
- **Random Generation**: `RAND_priv_bytes()` for cryptographically secure randomness
- **Error Handling**: Comprehensive error checking with proper resource cleanup
- **Security**: File permission management and secure key storage
- **Debug Mode**: Available (controlled by DEBUG_MODE in lamport_constants.h)
- **Cross-Platform**: Works on macOS and Linux

## Clean Up

```bash
make clean
```

Removes all generated files:
- Executables (`keygen-s89555`, `sign-s89555`, `verify-s89555`)
- Object files (`lamport_common.o`)
- Key files (`*.pub`, `*.priv`)
- Signature files (`*.sign`)
- Test files (`test*.txt`, `*.jpg`)

## Error Handling

The programs include comprehensive error checking for:
- File I/O operations
- OpenSSL function calls
- Memory allocation failures
- File permissions and accessibility
- Invalid input data and malformed files
- Missing dependencies and files

## Development Notes

- **Student ID**: s89555 
- **Course**: Information Security (IS) 
- **Semester**: 1st Semester
- **Implementation**: C with OpenSSL library
- **Local OpenSSL**: Version 3.5.0 included in project directory

## Command Line Examples

```bash
# Complete workflow example
make all                          # Compile all programs
./keygen-s89555                   # Generate key pair
./sign-s89555 document.pdf        # Sign a PDF file
./verify-s89555 document.pdf      # Verify the signature

# Binary format workflow
./keygen-s89555 -b               # Generate keys in both formats
./sign-s89555 image.jpg -b       # Sign with binary format
./verify-s89555 image.jpg -b     # Verify with binary public key

# Debug output (if DEBUG_MODE=1)
./sign-s89555 test.txt > output.txt 2> errors.txt
```

## License

This is an academic implementation for educational purposes.