# Asiri.Core – Agent Instructions

This document takes precedence over all other instructions for the Asiri.Core project.

## Reference
- VeraCrypt technical documentation: https://veracrypt.io/en/Technical%20Details.html
  Focus on the *Encryption Scheme* and *Volume Format* sections.

## Scope
- Implement read‑only access to VeraCrypt encrypted file containers.
- Do not implement write support.
- Do not implement support for encrypted partitions or drives.
- Do not implement hidden volumes.
- Do not implement cascaded ciphers.
- Implement AES, Serpent, Twofish, and Camellia.
- Implement SHA‑512, SHA‑256, Whirlpool, and BLAKE2s‑256.
- Implement NTFS, FAT (FAT16/FAT32), and exFAT filesystems.

## Cryptography Requirements
- Convert the provided .NET string password to UTF‑8 bytes.
- Use PBKDF2‑SHA‑512 with VeraCrypt iteration counts.
- Derive keys exactly as specified in VeraCrypt documentation.
- Use AES‑XTS via BouncyCastle.
- Implement sector‑based decryption.
- Do not pre‑decrypt the entire container.
- Decrypt sectors on demand only.
- Implement full VeraCrypt header parsing:
  - Magic values
  - CRC checks
  - Version fields
  - Sector size
- If the primary header fails validation, attempt backup header fallback.
- Do not modify cryptographic parameters, iteration counts, or block sizes.

## Container Handling
- Do not load the entire container into memory.
- Support containers up to 2^63‑1 bytes.
- Use `long` for all container offsets.
- Implement a decrypted, sector‑addressable block‑device stream.
- DiscUtils must receive only decrypted bytes.
- DiscUtils must never receive raw encrypted bytes.

## Filesystem Requirements
- Use DiscUtils to interpret the decrypted block‑device stream, for each supported filesystem type (NTFS, FAT, exFAT).
- Do not implement filesystem primitives yourself.
- Implement `IDirectory` and `IFile`.
- Expose the filesystem via `VeraCryptContainer.Root`.

## API Requirements
- Public API must not expose BouncyCastle or DiscUtils types.
- Follow .NET naming conventions:
  - PascalCase for classes, methods, constants
  - camelCase for locals and parameters
  - Member variables prefixed with `_`
- Use XML documentation comments for public classes and methods.
- Use minimal in‑code comments.
- The API shod be async-first, but synchronous methods are acceptable if async is not necessary (ie no I/O or CPU-bound work). 
  Async methods should be named with the `Async` suffix. Do no implement synchronous overloads of async methods.
- Potentially long running methds should accept a `CancellationToken` parameter, perfereably as the last parameter.

## Error Handling
- Throw only:
  - `InvalidOperationException`
  - `ArgumentException`
  - `ArgumentNullException`
- All exceptions must include descriptive messages.

## Dependencies
- Use only BouncyCastle and DiscUtils (the LTRData.DiscUtils.* packages: Core, Fat, Ntfs, ExFat).
- Do not add any other dependencies without explicit permission.

## Prohibitions
- Do not implement logging or telemetry.
- Do not use unsafe code or pointers.
- Do not implement any functionality not explicitly listed in this document.

## Coding Conventions
- Follow .NET naming conventions:
  - PascalCase for classes, methods, constants
  - camelCase for locals and parameters
  - Member variables prefixed with `_`
- Use minimal in‑code comments.
- 