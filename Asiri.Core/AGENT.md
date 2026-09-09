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
- Implement AES, Serpent, Twofish, and Camellia.
- Implement the following cascaded ciphers: AES-Twofish, AES-Twofish-Serpent, Serpent-AES,
  Serpent-Twofish-AES, Twofish-Serpent, Camellia-Serpent.
- Do not implement Kuznyechik, or any cascade involving it (Camellia-Kuznyechik,
  Kuznyechik-AES, Kuznyechik-Serpent-Camellia, Kuznyechik-Twofish).
- Implement SHA‑512, SHA‑256, Whirlpool, and BLAKE2s‑256.
- Implement opening a container secured by one or more keyfiles, supplied by the caller as ordinary
  files, mixed into the password per VeraCrypt's own algorithm. Do not implement security
  tokens/smart cards (PKCS#11) or folder-of-keyfiles as a keyfile source.
- Implement NTFS, FAT (FAT16/FAT32), and exFAT filesystems.

## Cryptography Requirements
- Convert the provided .NET string password to UTF‑8 bytes.
- Mix any supplied keyfiles into the password bytes, per VeraCrypt's own pool-mixing algorithm,
  before PBKDF2 - keyfiles are never stored in the header and never searched for; the caller must
  supply them, like the password.
- Use PBKDF2 with VeraCrypt's iteration counts, computed from the caller's PIM (Personal Iterations
  Multiplier) per VeraCrypt's own formula - 0 (the default) if none is supplied. PIM is never stored
  in the header and never searched for; the caller must supply it, like the password.
- Derive keys exactly as specified in VeraCrypt documentation.
- Use XTS mode, built on BouncyCastle's block ciphers, for every supported single cipher and cascade.
- Implement sector‑based decryption.
- Do not pre‑decrypt the entire container.
- Decrypt sectors on demand only.
- Implement full VeraCrypt header parsing:
  - Magic values
  - CRC checks
  - Version fields
  - Sector size
- If the primary header fails validation, attempt backup header fallback.
- Do not modify cryptographic parameters or block sizes. The PBKDF2 iteration count is the one
  parameter that legitimately varies, per PIM - see Cryptography Requirements above - not a
  deviation from this.

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
- Implement `IDirectory` and `IFile`, including their `Path`, `Parent`, attribute, and timestamp
  members (`IFileSystemEntry`), `IDirectory`'s `EnumerateFilesAsync`/`EnumerateDirectoriesAsync`,
  and `IFile.OpenReadAsync`.
- Each of the three filesystem backends (NTFS, FAT, exFAT) implements these independently, matching
  the existing pattern (no shared base class between the NTFS/FAT/exFAT directory or file wrappers).
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