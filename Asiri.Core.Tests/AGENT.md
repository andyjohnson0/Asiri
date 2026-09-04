# Asiri.Core.Tests – Agent Instructions

This document takes precedence over all other instructions for the Asiri.Core.Tests project.

## Scope
- Only write tests when specifically instructed to.
- Use xUnit with .NET 10.

## Coding Conventions
- Follow .NET naming conventions:
  - PascalCase for classes, methods, constants
  - camelCase for locals and parameters
  - Member variables prefixed with `_`
- Use minimal in‑code comments.

## Dependencies
- Use xUnit for tests.
- DiscUtils packages may be referenced directly, where a test needs to exercise DiscUtils' own API against Asiri.Core's stream, independent of the IDirectory/IFile abstraction (Asiri.Abstractions).
- Do not add any other dependencies without explicit permission.

## Test Containers
Test containers live in `Test Data`. Each has its own, independent password.

| File name                 | Password               | Encryption | Hash        | Filesystem |
|---------------------------|------------------------|------------|-------------|------------|
| AES_SHA-512_NTFS.hc       | A67m4$2c+V57#2AWq8d3   | AES        | SHA-512     | NTFS       |
| AES_SHA-512_FAT16.hc      | 85dRp6-OL72^L892WcqH   | AES        | SHA-512     | FAT16      |
| AES_SHA-512_FAT32.hc      | Uhf59~tTr30fH?52SD15   | AES        | SHA-512     | FAT32      |
| AES_SHA-512_EXFAT.hc      | kr2Y8+7vfENl08dR1cFn   | AES        | SHA-512     | exFAT      |
| SERPENT_SHA-512_EXFAT.hc  | 3f8L+2v9#1qW$5dR7gH0   | Serpent    | SHA-512     | exFAT      |
| TWOFISH_SHA-512_EXFAT.hc  | hR6ndf0-R9N7$qA4+=5B   | Twofish    | SHA-512     | exFAT      |
| CAMELLIA_SHA-512_EXFAT.hc | 6N7$K(r56Cf~Plhdr48D   | Camellia   | SHA-512     | exFAT      |
| AES_SHA-256_EXFAT.hc      | N^6reU50+3%FGc43>P8s   | AES        | SHA-256     | exFAT      |
| AES_WHIRLPOOL_EXFAT.hc    | FR7cg0-5%9SnmK02zRT2   | AES        | Whirlpool   | exFAT      |
| AES_BLAKE2s-256_EXFAT.hc  | 9Q8$P(m45Rf~Olnh79E6   | AES        | BLAKE2s-256 | exFAT      |

Passwords above are non-confidential (test-only) and may be embedded in the test code.
All of these encryption algorithms use 256‑bit keys and 128‑bit blocks, and all operate in XTS mode

## Verification Checklist
Every test container shares the same file/directory layout. Verify:

- The root directory contains `"test.txt"` with contents `"Hello, world!"`.
  Verify the file size matches the actual byte length.
- The root directory contains a subdirectory `"data"` containing:
  - `"subtest.txt"` with contents `"This is a test."`.
    Verify the file size matches the actual byte length.
  - `"image.png"` which must be **byte‑for‑byte identical** to the provided `image.png` in `Test Data`.
