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

## Test Categories
- Tests that are genuinely slow because they do real, repeated PBKDF2 work at production iteration
  counts - brute-force algorithm/hash detection in particular - must be tagged
  `[Trait("Category", "Integration")]`. This does not replace choosing efficient test data (e.g. a
  small, deliberately-chosen representative subset of containers rather than every fixture); it is
  for the residual cost that remains genuinely necessary, such as a test whose entire point is to
  exhaust the full real search space.
- The everyday/default run excludes them: `dotnet test --filter "Category!=Integration"`.
- Run them explicitly - e.g. before a release, or in a slower CI job - with
  `dotnet test --filter "Category=Integration"`, or `dotnet test` with no filter for everything.

## Dependencies
- Use xUnit for tests.
- DiscUtils packages may be referenced directly, where a test needs to exercise DiscUtils' own API against Asiri.Core's stream, independent of the IDirectory/IFile abstraction (Asiri.Abstractions).
- Do not add any other dependencies without explicit permission.

## Test Containers
Test containers live in `Test Data`. Each has its own, independent password. Passwords are non-confidential (test-only) and may be embedded in the test code.

### Encryption Test Containers

| File name                            | Encryption          | Hash        | Pim | Filesystem | Password                                                                         | Keyfile(s)                    |
|--------------------------------------|---------------------|-------------|-----|------------|----------------------------------------------------------------------------------|-------------------------------|
| AES_SHA-512_NTFS.hc                  | AES                 | SHA-512     |     | NTFS       | A67m4$2c+V57#2AWq8d3                                                             |                               |
| AES_SHA-512_FAT16.hc                 | AES                 | SHA-512     |     | FAT16      | 85dRp6-OL72^L892WcqH                                                             |                               |
| AES_SHA-512_FAT32.hc                 | AES                 | SHA-512     |     | FAT32      | Uhf59~tTr30fH?52SD15                                                             |                               |
| AES_SHA-512_EXFAT.hc                 | AES                 | SHA-512     |     | exFAT      | kr2Y8+7vfENl08dR1cFn                                                             |                               |
| SERPENT_SHA-512_EXFAT.hc             | Serpent             | SHA-512     |     | exFAT      | 3f8L+2v9#1qW$5dR7gH0                                                             |                               |
| TWOFISH_SHA-512_EXFAT.hc             | Twofish             | SHA-512     |     | exFAT      | hR6ndf0-R9N7$qA4+=5B                                                             |                               |
| CAMELLIA_SHA-512_EXFAT.hc            | Camellia            | SHA-512     |     | exFAT      | 6N7$K(r56Cf~Plhdr48D                                                             |                               |
| AES_SHA-256_EXFAT.hc                 | AES                 | SHA-256     |     | exFAT      | N^6reU50+3%FGc43>P8s                                                             |                               |
| AES_WHIRLPOOL_EXFAT.hc               | AES                 | Whirlpool   |     | exFAT      | FR7cg0-5%9SnmK02zRT2                                                             |                               |
| AES_BLAKE2s-256_EXFAT.hc             | AES                 | BLAKE2s-256 |     | exFAT      | 9Q8$P(m45Rf~Olnh79E6                                                             |                               |
|--------------------------------------|---------------------|-------------|-----|------------|----------------------------------------------------------------------------------|-------------------------------|
| AES-TWOFISH_SHA-512_EXFAT.hc         | AES/TwoFish         | SHA-512     |     | exFAT      | ExcLtHMJlW)8fb?VD?$L                                                             |                               |
| AES-TWOFISH-SERPENT_SHA-512_EXFAT.hc | AES/TwoFish/Serpent | SHA-512     |     | exFAT      | EWLe<8ZKGbpiV%Y56C6Z                                                             |                               |
| SERPENT-AES_SHA-512_EXFAT.hc         | Serpent/AES         | SHA-512     |     | exFAT      | H(g0d9$mM4V=al9N1QSM                                                             |                               |
| SERPENT-TWOFISH-AES_SHA-512_EXFAT.hc | Serpent/TwoFish/AES | SHA-512     |     | exFAT      | PT~gXCJW9jRZraD#Ja5e                                                             |                               |
| TWOFISH-SERPENT_SHA-512_EXFAT.hc     | TwoFish/Serpent     | SHA-512     |     | exFAT      | BacR-?#R7^2QlAYCOV6y                                                             |                               |
| CAMELLIA-SERPENT_SHA-512_EXFAT.hc    | Camellia/Serpent    | SHA-512     |     | exFAT      | AP9AF%XT~LRIKLPC$m=(                                                             |                               |
|--------------------------------------|---------------------|-------------|-----|------------|----------------------------------------------------------------------------------|-------------------------------|
| AES_SHA-512_EXFAT_PIM5.hc            | AES                 | SHA-512     | 5   | exFAT      | (a~ojGZpRQSSlTSzfjPU                                                             |                               |
| AES_WHIRLPOOL_EXFAT_PIM20.hc         | AES                 | Whirlpool   | 20  | exFAT      | bZ0VulQNxLOW^CK3k(lr                                                             |                               |
|--------------------------------------|---------------------|-------------|-----|------------|----------------------------------------------------------------------------------|-------------------------------|
| AES_SHA-512_EXFAT_KF1.hc             | AES                 | SHA-512     |     | exFAT      | wVMm#SsQRh5XdxPAr^mC                                                             | Keyfile1.bin                  |
| AES_SHA-512_EXFAT_KF1_EMPTYPW.hc     | AES                 | SHA-512     |     | exFAT      | (no password)                                                                    | Keyfile1.bin                  |
| AES_SHA-512_EXFAT_KF1_KF2.hc         | AES                 | SHA-512     |     | exFAT      | eCn8nAr-eK0tLhj)ceFP                                                             | Keyfile1.bin and Keyfile2.bin |
| AES_SHA-512_EXFAT_KF1_LONGPW.hc      | AES                 | SHA-512     |     | exFAT      | ~wacqaRl)mfCtNY>IGT%nhL~SLzHWW%9iPnHgPQt6Wj8s1F9(w=Jc<4<1pSaUkd%UTD4)-1h~KJAmhTq | Keyfile1.bin                  |

All of these encryption algorithms use 256‑bit keys and 128‑bit blocks, and all operate in XTS mode

Structure:
- test.txt — contents: "Hello, world!"
- data/ 
  - subtest.txt containing "This is a test."
  - image.png


### File System Test Containers

AES_SHA-512_EXFAT_ATTRS.hc 
— AES / SHA-512 / exFAT 
— password ZlWjwD>EW)RP76IiMKfz
- Structure:
  - test.txt — standard content, default attributes.
  - readonly.txt — small known content, ReadOnly attribute (attrib +r).
  - hidden.txt — Hidden attribute (attrib +h).
  - system.txt — System attribute (attrib +s).
  - data/ — standard, containing subtest.txt + image.png.
  - other/ — a second top-level subdirectory, containing five files.


## Verification Checklist
Every test container shares the same file/directory layout. Verify:

- The root directory contains `"test.txt"` with contents `"Hello, world!"`.
  Verify the file size matches the actual byte length.
- The root directory contains a subdirectory `"data"` containing:
  - `"subtest.txt"` with contents `"This is a test."`.
    Verify the file size matches the actual byte length.
  - `"image.png"` which must be **byte‑for‑byte identical** to the provided `image.png` in `Test Data`.
