# Asiri.Export – Agent Instructions

This document takes precedence over all other instructions for the Asiri.Export project.

## Scope
- Export a VeraCrypt container's decrypted filesystem to a real disk image - none of it encrypted,
  and none of it interpreted by Asiri or DiscUtils on the way out - for handing to a tool, person,
  a real OS's own mount path, or a physical medium (a USB drive, for example) entirely outside
  Asiri.
- `FileSystemExtractor` is the sole public entry point, built against `Asiri.Core`'s
  `IFileSystemExportSource` interface, not `VeraCryptContainer` directly. This project exists
  specifically to keep DiscUtils' virtual-disk container packages (Vhd, and eventually others - see
  issue #13) out of `Asiri.Core`'s own dependency footprint, since not every `Asiri.Core` consumer
  wants them (constrained clients, e.g. mobile).
- `FileSystemExportFormat` covers real, usable disk formats only: a bare raw image, and VHD (with or
  without a partition table). Do not add diagnostic-only formats here (e.g. boot-sector-only export)
  - those live in `Asiri.Diagnostics`, reading through the same `IFileSystemExportSource` interface
  directly.
- Do not implement tests in this project unless asked; if asked, mirror `Asiri.Core.Tests`'
  conventions (real VeraCrypt test containers, not synthetic ones, for this project's own export
  format tests).
- Do not add other projects or dependencies beyond `Asiri.Core` and the DiscUtils virtual-disk
  packages actually needed for a supported `FileSystemExportFormat`, without explicit permission.

## Coding Conventions
- Follow .NET naming conventions:
  - PascalCase for classes, methods, constants
  - camelCase for locals and parameters
  - Member variables prefixed with `_`
- Use XML documentation comments for public classes and methods.
- Use minimal in-code comments.
- The API should be async-first; synchronous methods are acceptable only where no I/O or CPU-bound
  work is involved. Async methods are named with the `Async` suffix.

## Prohibitions
- Do not implement logging or telemetry.
- Do not use unsafe code or pointers.
- Do not implement any functionality not explicitly listed in this document.
