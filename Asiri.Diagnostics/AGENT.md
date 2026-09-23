# Asiri.Diagnostics – Agent Instructions

This document takes precedence over all other instructions for the Asiri.Diagnostics project.

## Reference
- VeraCrypt technical documentation: https://veracrypt.io/en/Technical%20Details.html
- VeraCrypt's own source (github.com/veracrypt/VeraCrypt) - the primary source for anything this
  tool needs to cross-check against real VeraCrypt behaviour, since its whole purpose is comparing
  Asiri's own behaviour against a real, already-running VeraCrypt.

## Scope
- A standalone console tool for diagnosing Asiri.Core containers against a real, already-running
  VeraCrypt - not part of the Asiri library or its public API, and never referenced by any other
  project in this solution.
- `Program.cs` is only ever a command dispatcher: it parses the first argument to pick a command and
  hands the rest of the arguments to that command's own class. Each command lives in its own class
  (see `CompareCommand`) and owns its own argument parsing, usage text, and logic - add a new
  diagnostic as a new command class, not by growing `Program.Main` or an existing command.
- `dump-boot-sector` (`DumpBootSectorCommand`): opens a container via the ordinary
  `VeraCryptContainer.OpenAsync` API and writes just its boot sector (the first 512 bytes of the
  decrypted filesystem) to a file, via `IFileSystemExportSource.CopyBytesAsync` directly - the same
  minimal interface `Asiri.Export`'s `FileSystemExtractor` is built on. Lives here rather than in
  `Asiri.Export` because a bare boot sector isn't a usable disk image on its own the way
  `Asiri.Export`'s formats are - it's diagnostic-only, and reading it needs no DiscUtils dependency.
- `compare` (`CompareCommand`): decrypts a container's data area directly via `HeaderParser`/
  `SectorDecryptor` - never through `VeraCryptContainer` or DiscUtils, so no filesystem
  interpretation happens on Asiri's side - and compares it byte-for-byte against the same range read
  raw off a drive letter a real, already-running VeraCrypt has mounted that same container onto,
  after first cross-checking the raw volume's own reported size against Asiri's header (a mismatch
  there means the drive letter and the container being decrypted may not even be the same volume,
  or that VeraCrypt is computing a different size for some other reason worth its own
  investigation - either way, a byte-level mismatch shouldn't be read as a decryption bug until
  that's ruled out). Used to determine whether a "VeraCrypt mounts it but Windows won't recognise
  the filesystem" failure is a decryption mismatch or something downstream of decryption.
- Use only Asiri.Core (and its Asiri.Abstractions dependency) plus the .NET BCL. Do not add other
  dependencies without being explicitly asked to.
- Prefer a BCL primitive over a manual P/Invoke wherever one exists (e.g. `File.OpenHandle` over a
  `CreateFile` P/Invoke) - P/Invoke only where there is genuinely no managed equivalent (e.g.
  `DeviceIoControl` for `IOCTL_DISK_GET_LENGTH_INFO`, which has none).
- This is a diagnostic tool for a single developer's own local use, not a distributed or
  security-sensitive one - credentials passed as plain command-line arguments (visible in process
  listings and shell history) are an accepted, deliberate tradeoff here, not an oversight.
- Do not implement tests.
- Do not add other projects without being explicitly asked to.
- Do not modify Asiri.Core.

## Coding Conventions
- Follow .NET naming conventions:
  - PascalCase for classes, methods, constants
  - camelCase for locals and parameters
- Use minimal in-code comments; prefer one that explains *why* a value or approach was chosen -
  especially anything verified against VeraCrypt's own source - over one restating what the code
  does.
- Use async where appropriate, matching Asiri.Core's own async-first convention for I/O.
