#!/bin/bash

# Set output executable name
OUTPUT="mass"

# Find all .c files in current and subdirectories
SRC_FILES=$(find . -type f -name "*.c")

# Compile with GCC and link necessary libraries
echo "Compiling..."
gcc $SRC_FILES -o $OUTPUT -lcurl -lmicrohttpd -lsqlite3 -ljansson -lssl -lcrypto

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit $?
fi

echo "Compilation successful."
./$OUTPUT
