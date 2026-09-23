# Asiri.Core – Agent Instructions

This document takes precedence over all other instructions for the Asiri.Core project.

## Reference
- VeraCrypt technical documentation: https://veracrypt.io/en/Technical%20Details.html
  Focus on the *Encryption Scheme* and *Volume Format* sections.

## Scope
- Implement read access to VeraCrypt encrypted file containers.
- Implement write access to VeraCrypt encrypted file containers, gated solely by
  `VeraCryptContainer.AccessMode` (fixed for the whole session by whichever `ContainerAccessMode`
  the container was opened or created with - there is no separate runtime arm/disarm switch).
  Limited to fixed-size containers: do not implement growing or shrinking a container's size.
- Implement changing an already-open container's password, keyfiles, PIM, and/or hash algorithm
  (`VeraCryptContainer.ChangeCredentialsAsync`, an instance method requiring
  `ContainerAccessMode.ReadWrite` - having opened the container at all is itself the proof of the
  current credentials, so there is nothing left to re-authenticate), verified against VeraCrypt's
  own source (Common/Password.c's `ChangePwd`): the master and secondary keys are never changed,
  only the header's own encryption key (re-derived with a fresh random salt) is, and both the
  primary and backup header are rewritten, each with its own independent salt, through the
  container's own already-open stream rather than a second handle on the same file. The encryption
  algorithm cannot change this way. Two scope reductions relative to real VeraCrypt, both deliberate:
  no multi-pass anti-forensic overwrite of the old header location, and no preservation of the
  container file's own timestamps.
- Implement creating a brand new container (`VeraCryptContainer.CreateAsync`): a freshly generated
  master key, a header built from scratch (not re-encrypting an existing one, unlike
  `ChangeCredentialsAsync`), and the chosen filesystem formatted via DiscUtils directly onto the
  container's encrypted stream. The caller-specified size is the container's TOTAL FILE SIZE,
  verified against VeraCrypt's own source (Common/Format.c's `TCFormatVolume`) - VeraCrypt's fixed
  256 KiB header overhead comes out of that, not on top of it. An optional cluster size may be
  requested, but only for exFAT: verified against DiscUtils' own source, its NTFS and FAT formatters
  give no way to override their own fixed/size-derived cluster size at all, so a non-null value for
  either of those is rejected rather than silently ignored. The space between each 512-byte header
  region and the area where a hidden volume's own header could reside (both the primary side, before
  the data area, and the backup side, before end-of-file) is filled with cryptographically random
  data, not left zero - verified against VeraCrypt's own Volume Format Specification, which documents
  this space as containing random data in every genuine volume regardless of whether a hidden volume
  is actually present, precisely so its contents give no clue either way. The entire data area is
  likewise filled with random data, encrypted through the container's own stream, before the chosen
  filesystem is formatted on top of it - also verified against the Volume Format Specification, which
  documents this as happening "right before volume formatting begins": a filesystem formatter only
  ever writes its own metadata, never the free clusters it marks unused, so without this fill those
  clusters would remain the raw, unencrypted zero bytes a newly-extended file starts as, rather than
  looking like every other part of a genuine VeraCrypt volume.
- Implement `IFileSystemExportSource`, and have `VeraCryptContainer` implement it explicitly
  (`Length`, `FileSystemType`, `CopyBytesAsync`) - the minimal, dependency-free surface that
  `Asiri.Export`'s `FileSystemExtractor` builds real disk-container exports on top of. Do not
  implement any export-format-specific logic (raw image, VHD, etc.) here: that all lives in
  `Asiri.Export` specifically so it isn't a dependency every `VeraCryptContainer` consumer has to
  take - see `Asiri.Export/AGENT.md`. The one exception is the diagnostic boot-sector-only export,
  which lives in `Asiri.Diagnostics` and reads through this same interface directly.
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
- Implement sector‑based decryption, and, when writing, sector-based encryption (XTS operates on
  whole data units, so a write smaller than a sector requires a read-modify-write of that sector).
- Do not pre‑decrypt the entire container.
- Decrypt sectors on demand only.
- Implement full VeraCrypt header parsing:
  - Magic values
  - CRC checks
  - Version fields
  - Sector size
- `OpenOptions.HeaderPreference` (`HeaderType`, default `Auto`): `Auto` tries the primary header and
  falls back to the backup header if it fails validation. `Primary`/`Backup` explicitly try only
  that one region, with no fallback to the other, verified against VeraCrypt's own source
  (`Core/MountOptions.h`'s `UseBackupHeaders`, `Volume/Volume.cpp`'s `Volume::Open`) - VeraCrypt's own
  mount-time choice is a single, non-fallback option too; its "silently recovers from a damaged
  primary header" behaviour is a GUI-level retry heuristic on top of that
  (`Main/GraphicUserInterface.cpp`, gated behind repeated incorrect-password attempts), not a core
  behaviour.
- `OpenAsync`/`CreateAsync` both return `OpenResult` (the container, plus which header region was
  actually used - never `Auto`, and always `Primary` for `CreateAsync`), not `VeraCryptContainer`
  directly. Deliberate: which header region resolved is a one-time fact about that particular
  open/create call, not ongoing container state - nothing the container does later ever consults
  it again, unlike `Algorithm`/`HashAlgorithm`/`AccessMode`, which genuinely are read again (e.g.
  by `ChangeCredentialsAsync`). Do not add a `HeaderType`-shaped property back onto
  `VeraCryptContainer` itself for this reason.
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
- Implement the write members of `IFileSystemEntry`/`IDirectory`/`IFile`: `RenameAsync`,
  `MoveToAsync`, `SetAttributesAsync`, `SetCreationTimeUtcAsync`, `SetLastWriteTimeUtcAsync`,
  `IDirectory.CreateDirectoryAsync`/`CreateFileAsync`/`DeleteAsync`, and
  `IFile.OpenWriteAsync`/`DeleteAsync`. Each throws if the container is not currently open for
  writing (see Scope above).
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
  - `ObjectDisposedException` - used exclusively for "this container has already been closed"
    (`ContainerLifetime.ThrowIfClosed`), never for anything else. The more idiomatic .NET choice
    for that specific condition than `InvalidOperationException` would be, so it's an accepted
    fourth type rather than a violation of this rule.
- All exceptions must include descriptive messages.
- Never let an underlying dependency's own exception type (DiscUtils, BouncyCastle, or a raw
  `System.IO` failure) propagate unwrapped - catch it and rethrow as one of the types above, with
  the original as `InnerException`, so a caller only ever needs to handle this fixed set.

## Dependencies
- Use only BouncyCastle and DiscUtils (the LTRData.DiscUtils.* packages: Core, Fat, Ntfs, ExFat -
  no DiscUtils virtual-disk container package such as Vhd: those are `Asiri.Export`'s dependency,
  not this project's, precisely so a consumer who never exports doesn't take them on transitively).
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