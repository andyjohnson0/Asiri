# Asiri.Abstractions – Agent Instructions

This document takes precedence over all other instructions for the Asiri.Abstractions project.

## Scope
- Define the filesystem contracts that a VeraCrypt container exposes: `IDirectory`, `IFile`,
  `IFileSystemEntry`.
- Interfaces and their supporting types only. Do not add implementations here — those belong in
  Asiri.Core (or any other project that chooses to implement these contracts).
- Keep this project dependency-free, so that other software can target these interfaces without
  pulling in Asiri.Core's BouncyCastle/DiscUtils dependencies.

## API Requirements
- Follow .NET naming conventions:
  - PascalCase for classes, methods, constants
  - camelCase for locals and parameters
- Use XML documentation comments for public types and members.
- Use minimal in‑code comments.

## Dependencies
- None. Do not add any package or project references without explicit permission.

## Prohibitions
- Do not implement logging or telemetry.
- Do not implement any functionality not explicitly listed in this document.
