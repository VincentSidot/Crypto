# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2024-09-10
First version of the project.
### Added
- Gernerate RSA keys.
- Encrypt and decrypt files. (Using AES and RSA)

## [1.0.0] - 2024-09-13

### Updated
- The encryption scheme has been updated to use new `crypto` crate. (Now the data are encrypted
  by chunks instead of all at once)

## [1.0.1] - 2024-09-17

### Updated
- The cli app while now decrypt the data to stdout if no output file is provided.
- The cli app now decrypt the data by chunks instead of all at once. (This is usefull for
  corrupted files). Maybe I should add correction codes in the future.