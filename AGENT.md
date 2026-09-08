# Asiri Project – Agent Instructions

This document takes precedence over all other instructions, except that each project listed below
has its own `AGENT.md`, which takes precedence over this document for work within that project.

## What this project is
Read-only access to VeraCrypt encrypted file containers, from .NET, without depending on the
VeraCrypt application itself. See `README.md` for the full picture, including what is and isn't
supported.

## Solution structure
- `Asiri.Abstractions` — dependency-free filesystem contracts (`IDirectory`, `IFile`,
  `IFileSystemEntry`). See `Asiri.Abstractions/AGENT.md`.
- `Asiri.Core` — the library itself: header parsing, sector-level decryption, cipher/hash
  implementations, DiscUtils-backed filesystem adapters, and the public `VeraCryptContainer` entry
  point. See `Asiri.Core/AGENT.md`.
- `Asiri.Core.Tests` — xUnit tests, run against real VeraCrypt test containers. See
  `Asiri.Core.Tests/AGENT.md` for the test container catalogue and verification checklist.
- `Asiri.ContainerBrowser` — a WPF reference application demonstrating `Asiri.Core` as a consumer
  would use it. See `Asiri.ContainerBrowser/AGENT.md`.

## Project-wide scope
- Implement read-only access to VeraCrypt encrypted file containers.
- Do not implement write support.
- Do not implement support for encrypted partitions or drives.
- Do not implement hidden volumes.
- Supported encryption algorithms: AES, Serpent, Twofish, Camellia, and the cascades AES-Twofish,
  AES-Twofish-Serpent, Serpent-AES, Serpent-Twofish-AES, Twofish-Serpent, Camellia-Serpent.
- Supported hash algorithms: SHA-512, SHA-256, Whirlpool, BLAKE2s-256.
- Support opening a container with a non-default PIM (Personal Iterations Multiplier), supplied by
  the caller - VeraCrypt does not store it in the container.
- Support opening a container secured by one or more keyfiles, supplied by the caller as ordinary
  files - VeraCrypt does not store keyfiles in the container either. Do not implement security
  tokens/smart cards (PKCS#11) or folder-of-keyfiles as a keyfile source.
- Supported filesystems: NTFS, FAT (FAT16/FAT32), exFAT.
- Do not implement Kuznyechik or Streebog (GOST algorithms).

The cryptography, container-handling, filesystem, public-API, and error-handling requirements that
govern the library's implementation live in `Asiri.Core/AGENT.md`, not here, to avoid the two
documents drifting apart.

## Project-wide prohibitions
- Do not implement logging or telemetry.
- Do not use unsafe code or pointers.
- Do not implement any functionality not explicitly requested.
- Do not add third-party dependencies without explicit permission. Each project's own `AGENT.md`
  lists what it is already permitted to depend on.
