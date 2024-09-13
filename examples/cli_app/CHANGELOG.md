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