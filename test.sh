#!/bin/bash

TARGET_DIR=./_tmp

function cleanup {
    rm -rf $TARGET_DIR
}

trap cleanup EXIT

function test {
    mkdir -p $TARGET_DIR
    start=$(date +%s)
    # Generate the keys
    $1 keygen $TARGET_DIR/key
    if [ $? -ne 0 ]; then
        echo "Failed to generate keys"
        exit 1
    fi
    # Encrypt the file
    $1 encrypt ./tests/hello.txt $TARGET_DIR/key.pub $TARGET_DIR/hello.enc
    if [ $? -ne 0 ]; then
        echo "Failed to encrypt file"
        exit 1
    fi
    # Decrypt the file
    $1 decrypt $TARGET_DIR/hello.enc $TARGET_DIR/key $TARGET_DIR/hello.dec
    if [ $? -ne 0 ]; then
        echo "Failed to decrypt file"
        exit 1
    fi
    end=$(date +%s)
    # Compare the files
    diff ./tests/hello.txt $TARGET_DIR/hello.dec
    if [ $? -ne 0 ]; then
        echo "Files are not the same"
        exit 1
    fi
    echo "Files are the same"
    echo "Time taken: $((end-start)) seconds"
}

# Handle debug mode
cargo build > /dev/null 2>&1
echo "Running in debug mode"
test ./target/debug/crypto-files

# Handle release mode
cargo build --release > /dev/null 2>&1
echo "Running in release mode"
test ./target/release/crypto-files


