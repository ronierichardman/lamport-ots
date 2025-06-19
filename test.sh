#!/bin/bash

# Test script for Lamport one-time signature implementation

echo "=== Lamport One-Time Signature Test Suite ==="
echo

# Compile the programs
echo "1. Compiling programs..."
make clean && make all
if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi
echo "Compilation successful"
echo

# Test 1: Key generation
echo "2. Testing key generation..."
./keygen-s89555
if [ $? -eq 0 ] && [ -f "lamport-ots.pub" ] && [ -f "lamport-ots.priv" ]; then
    echo "Key generation successful"
    # Check file permissions
    perms=$(stat -f "%A" lamport-ots.priv 2>/dev/null || stat -c "%a" lamport-ots.priv 2>/dev/null)
    echo "  Private key permissions: $perms"
else
    echo "Key generation failed"
    exit 1
fi
echo

# Test 2: Valid signature
echo "3. Testing valid signature..."
cp ./ref/test.txt test1.txt
if [ ! -f "test1.txt" ]; then
    echo "Test document creation failed"
    echo "This is a test document for Lamport signature verification." > test1.txt
fi
./sign-s89555 test1.txt
if [ $? -eq 0 ] && [ -f "test1.txt.sign" ]; then
    echo "Signing successful"
    ./verify-s89555 test1.txt
    if [ $? -eq 0 ]; then
        echo "Valid signature verification successful"
    else
        echo "Valid signature verification failed"
        exit 1
    fi
else
    echo "Signing failed"
    exit 1
fi
echo

# Test 3: Invalid signature (modified document)
echo "4. Testing invalid signature (modified document)..."
echo "This is a MODIFIED test document." > test2.txt
cp test1.txt.sign test2.txt.sign
./verify-s89555 test2.txt
if [ $? -eq 1 ]; then
    echo "Invalid signature correctly detected"
else
    echo "Invalid signature not detected"
    exit 1
fi
echo

# Test 4: Missing document during signing
echo "5. Testing missing document during signing..."
./sign-s89555 nonexistent.txt
if [ $? -ne 0 ]; then
    echo "Missing document error correctly handled"
else
    echo "Missing document error not handled"
    exit 1
fi
echo

# Test 5: Missing document during verification
echo "6. Testing missing document during verification..."
./verify-s89555 nonexistent.txt
if [ $? -ne 0 ]; then
    echo "Missing document during verification correctly handled"
else
    echo "Missing document during verification not handled"
    exit 1
fi
echo

# Test 6: Missing signature file
echo "7. Testing missing signature file..."
echo "Another test document" > test3.txt
./verify-s89555 test3.txt
if [ $? -ne 0 ]; then
    echo "Missing signature file correctly handled"
else
    echo "Missing signature file not handled"
    exit 1
fi
echo

# Test 7: Verify a given signature and public key
echo "8. Testing verification of a given signature and public key..."
rm -f *.pub 
if [ $? -ne 0 ]; then
    echo "Verification program compilation failed!"
    exit 1
fi
cp ./ref/document.jpg document.jpg
cp ./ref/document.jpg.sign document.jpg.sign
cp ./ref/lamport-ots.pub lamport-ots.pub
./verify-s89555 document.jpg
if [ $? -eq 0 ]; then
    echo "Given signature verification successful"
else
    echo "Given signature verification failed"
    exit 1
fi

echo "=== All tests passed! ==="
echo
echo "Files created:"
ls -la *.pub *.priv *.sign test*.txt *.jpg
# ls -la *.pub *.priv *.sign test*.txt 2>/dev/null || echo "No files to list"
echo "Cleaning up..."
# Clean up generated files
make clean
