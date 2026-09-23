# Asiri Project – Agent Instructions

This document takes precedence over all other instructions, except that each project listed below
has its own `AGENT.md`, which takes precedence over this document for work within that project.

## What this project is
Access — read, and opt-in write — to VeraCrypt encrypted file containers, from .NET, without
depending on the VeraCrypt application itself. See `README.md` for the full picture, including what
is and isn't supported.

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
- `Asiri.Export` — exports a container's decrypted filesystem to a real disk image (raw, or wrapped
  in a VHD). Kept separate from `Asiri.Core` so its DiscUtils virtual-disk dependency isn't forced
  on every `Asiri.Core` consumer. See `Asiri.Export/AGENT.md`.

## Project-wide scope
- Implement read access to VeraCrypt encrypted file containers.
- Implement write access to VeraCrypt encrypted file containers - opt-in and off by default, gated
  solely by `ContainerAccessMode`, fixed for the whole session by whichever mode the container was
  opened or created with (no separate runtime arm/disarm switch) - and limited to fixed-size
  containers: do not implement growing or shrinking a container's size.
- Implement changing an already-open, `ContainerAccessMode.ReadWrite` container's password,
  keyfiles, PIM, and/or hash algorithm (`VeraCryptContainer.ChangeCredentialsAsync`) without
  touching its contents - the master/secondary key never changes, only the header's own encryption
  key does. The encryption algorithm itself cannot change this way, matching VeraCrypt's own
  behaviour. Unlike VeraCrypt, do not implement its optional multi-pass anti-forensic overwrite of
  the old header, and do not preserve the container file's own timestamps - both deliberate scope
  reductions, not oversights.
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

## Release Procedure

Follow this whenever a milestone (major or minor version, e.g. `v<X.Y>`) is ready to ship. It
assumes the milestone was developed on its own branch (`v<X.Y>`), itself branched from
`development`, itself branched from `main` - matching this project's established branching pattern -
with each issue landing as its own commit (or squash-merged feature branch) directly on `v<X.Y>`.

### 1. Before starting
- Confirm every issue actually in the `v<X.Y>` milestone is either done or deliberately being
  deferred (moved to a new/different milestone) - check `gh issue list --milestone v<X.Y>` rather
  than assuming the milestone's contents match intent.
- Read through the README and each touched project's `AGENT.md` for gaps against what actually
  shipped this cycle - new features are easy to implement without updating the docs that describe
  them; check rather than assume.

### 2. Version metadata
- Bump `<Version>` in every project's `.csproj` to `<X.Y>.0`, all in one commit.
- Update the README's own "Pre-release, version `...`" line to match.

### 3. Merge to development and main
- Merge `v<X.Y>` into `development` with `--no-ff` and a narrative commit message summarising what
  shipped, referencing the closed issues by number (e.g. "closing #<a>, #<b>, #<c>") - but never
  using GitHub's auto-close phrasing ("Closes #N", "Fixes #N", etc.) in this or any commit message.
  That auto-closes the issue the moment the commit reaches `main`, before it can be closed
  explicitly with its own comment - confirmed the hard way during the v0.3 release.
- Fast-forward `main` to `development`.
- After each step: full solution build, plus a full run of every test project in the solution (not
  just one) - confirm 0 failures before proceeding.

### 4. Push and branch cleanup
- Push `main` to `origin` only. Never push `development` or the release branch itself - those stay
  local.
- Verify the merge landed correctly: `git diff <release-branch> main` should be empty.
- Check for any existing branch or tag already named `v<X.Y>` before deleting the release branch or
  creating the release tag - flag any collision rather than silently overwriting.
- Delete the `v<X.Y>` branch. A safe `git branch -d` will likely refuse (squash/no-ff history rarely
  fast-forwards); `-D` is fine once the empty-diff check above has already confirmed nothing is lost.

### 5. Close out issues and the milestone
- Close each issue actually shipped in this release individually, via
  `gh issue close <n> --comment "..."` with a short, specific note on what landed - never rely on
  commit-message auto-close.
- Once every issue in the milestone is closed, close the milestone itself.
- Leave anything explicitly deferred or split out (e.g. issues moved to a future milestone or the
  backlog) untouched.

### 6. Build the release asset
- This project ships **library-only** releases: the zip contains only the packaged library
  projects - identifiable by having `PackageLicenseExpression`/`PackageProjectUrl` set in their
  `.csproj` (currently `Asiri.Abstractions`, `Asiri.Core`, `Asiri.Export`) - plus their full
  transitive dependency closure (BouncyCastle, DiscUtils.*, etc.). Utility/app projects
  (`Asiri.ContainerBrowser`, `Asiri.Diagnostics`) are never included as binaries; the release notes
  point at building them from source instead.
- Use `dotnet publish` (Release config), not `dotnet build` - `build` alone does not copy transitive
  NuGet dependency DLLs into a netstandard2.0 library's output folder; `publish` does.
- Zip via PowerShell's `Compress-Archive` - `zip` is not available in this Windows/git-bash
  environment.
- Include the built DLLs + PDBs, README.md, and LICENSE.md in the zip.

### 7. Release notes and publish
- Write release notes covering: any breaking API changes (called out explicitly, with a ⚠️ heading,
  matching prior releases), what's new (one bullet per shipped issue), and the asset's own contents.
- Include the standing "this project is agent-written" disclaimer and Claude Code attribution line,
  matching every prior release's notes.
- Create an annotated tag `v<X.Y>`, push it.
- `gh release create v<X.Y> <asset-zip> --title "Asiri v<X.Y>.0" --notes-file <notes>`.
