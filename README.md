# Asiri

Asiri provides standalone access to [VeraCrypt](https://veracrypt.io/) encrypted file containers from
.NET, without depending on the VeraCrypt application itself. Given a container file and its password,
it derives the keys, decrypts the volume header, and exposes the container's filesystem — files and
directories — through a small, dependency-free abstraction that a consuming application can browse
and read from directly. Write access — creating, deleting, renaming, and moving files and
directories, and modifying their content and attributes — is also available, opt-in and off by
default.

"Asiri" is the Swahili word for "secret".

## ⚠️ This code is agent-written

Every line of code, test, and piece of documentation in this repository was written by
**Claude Sonnet 5** (Anthropic), acting as a coding agent inside Claude Code, working from
instructions given by **Andrew Johnson** ([andy@andyjohnson.uk](mailto:andy@andyjohnson.uk),
[andyjohnson.uk](https://andyjohnson.uk)), who prompted, reviewed, and directed the work.

This is a hobby/experimental project exploring what an AI coding agent can produce end-to-end. It
has **not** undergone independent security review or a cryptographic audit. Read access is the
mature, well-exercised path. Write access exists, is newer and opt-in, and has now been exercised
against a real, running VeraCrypt: a container created with `CreateAsync` was confirmed to mount and
have its filesystem recognised by VeraCrypt, and content changes were round-tripped through both a
real VeraCrypt mount and Asiri.ContainerBrowser — but this was a manual, one-off check, not the
exhaustive automated coverage across every filesystem/cipher combination that read access has. Treat
the whole library accordingly: do not use it as your only means of accessing data you care about, and
do not rely on it in any security-critical context without your own review.

**⚠️ Write access is opt-in and pre-release. Only use it on containers you have backed up.** It has
been confirmed to work against a real, running VeraCrypt (see above), but not yet across the full
range of filesystems, ciphers, and scenarios that read access covers. A bug in the write path could
corrupt a container beyond what VeraCrypt itself can open.

**⚠️ Changing a container's password/keyfiles is also pre-release and unverified against real
VeraCrypt. Only use it on containers you have backed up.** This rewrites the volume header in
place; a bug here risks a worse outcome than a filesystem write bug — the container could become
permanently unopenable, with no data corrupted but no way to reach it either.

One thing that is independent of the agent: every real VeraCrypt container in
`Asiri.Core.Tests/Test Data` was created using the actual VeraCrypt application, by Andrew, not
generated or shaped by the agent. The agent never had the ability to make a test container's
ciphertext agree with its own understanding of the format. As a result, mutating any test
container's bytes and re-running the test suite will produce failures — a simple, independent check
that the read path is exercising real decryption against real VeraCrypt output, not just checking the
code's assumptions against themselves.

Write access now has a first, manual version of an equivalent independent check: a container created
with `CreateAsync` was confirmed to mount and have its filesystem recognised by a real, running
VeraCrypt, and content round-tripped through both a real VeraCrypt mount and
Asiri.ContainerBrowser was confirmed consistent on both sides — see `Asiri.Diagnostics`, a standalone
tool built for exactly this kind of cross-check against a live VeraCrypt process. This is not yet
automated or exhaustive the way the read path's real-fixture tests are, so treat it as a first data
point, not full parity with read access's verification. Changing a container's password or keyfiles
has not been separately verified this way — the caution above still applies to that in full.

## Status

Pre-release, version `0.4.0`. The public API may still change.

## What's supported

Asiri implements the subset of the VeraCrypt volume format needed to open a standard, non-system
container file and read its contents.

**Encryption algorithms** (XTS mode, 256-bit keys / 128-bit blocks):
- AES, Serpent, Twofish, Camellia (single cipher)
- AES-Twofish, AES-Twofish-Serpent, Serpent-AES, Serpent-Twofish-AES, Twofish-Serpent,
  Camellia-Serpent (cascades of two or three ciphers)

**Hash algorithms** (PBKDF2 key derivation):
- SHA-512
- SHA-256
- Whirlpool
- BLAKE2s-256

**PIM** (Personal Iterations Multiplier) — a container created with a non-default PIM can be opened
by supplying it as an optional `pim` parameter to `OpenAsync`; like the password, VeraCrypt does not
store it in the container and it is never guessed at.

**Keyfiles** — one or more ordinary files can be supplied as an optional `keyFiles` parameter to
`OpenAsync`, mixed into the password exactly as VeraCrypt itself does, including keyfile-only
containers (an empty password). Security tokens/smart cards and folder-of-keyfiles are not
supported — only explicitly-supplied individual files.

**Filesystems** (via [DiscUtils](https://github.com/LTRData/DiscUtils)):
- NTFS
- FAT (FAT16 and FAT32)
- exFAT

**Filesystem metadata and navigation** — beyond listing and reading files, `IFileSystemEntry`
exposes `Path`, `Parent`, `GetAttributesAsync()` (read-only, hidden, system, etc), and
`GetCreationTimeUtcAsync()`/`GetLastWriteTimeUtcAsync()`; `IDirectory` adds `EnumerateFilesAsync()`/
`EnumerateDirectoriesAsync()` with an optional search pattern; `IFile` adds `OpenReadAsync()` for
streaming a large file's contents instead of buffering it all via `ReadAllBytesAsync()`.

**Write access** (opt-in, off by default — see the caution above): opening a container with
`ContainerAccessMode.ReadWrite` enables creating, deleting, renaming, and moving files and
directories, setting attributes and timestamps, and writing file content via
`IFile.OpenWriteAsync()`. `ContainerAccessMode` is fixed for the container's whole session — there
is no separate runtime switch to arm or disarm afterward — and only fixed-size containers are
supported for writing: Asiri cannot grow or shrink a container, so operations that would change its
size beyond its existing free space behave the same as they would on a full disk.

**Changing a password, keyfiles, PIM, and/or hash algorithm** (opt-in, pre-release — see the caution
above): `VeraCryptContainer.ChangeCredentialsAsync`, an instance method on an already-open,
`ContainerAccessMode.ReadWrite` container, rewrites its volume header — both the primary and backup
copies, each with its own independent random salt — under a freshly derived key, without touching
the container's contents: the master and secondary keys that actually protect the data are never
changed. Verified against VeraCrypt's own source, not just its documentation. Having opened the
container with `ReadWrite` access at all is itself the proof of its current credentials, so unlike a
static method taking both old and new credentials, only the new ones need supplying here. Two scope
reductions relative to real VeraCrypt, both deliberate: no multi-pass anti-forensic overwrite of the
old header location (VeraCrypt's own optional defense against recovering it via
magnetic/flash remanence), and no preservation of the container file's own timestamps. Like write
access, the encryption algorithm itself cannot change this way — only the header's own encryption key
can, matching VeraCrypt's own behaviour.

**Not supported, by design:**
- Dynamic (growable) containers, or growing/shrinking a container's size.
- Hidden volumes.
- Encrypted partitions or drives — only container *files*.
- The Kuznyechik cipher or Streebog hash (GOST algorithms), including every cascade involving
  Kuznyechik (Camellia-Kuznyechik, Kuznyechik-AES, Kuznyechik-Serpent-Camellia, Kuznyechik-Twofish).
- Security tokens / smart cards (PKCS#11) as a keyfile source.

All cryptographic primitives are provided by [BouncyCastle](https://github.com/bcgit/bc-csharp) —
Asiri does not implement its own cryptography, only the VeraCrypt-specific header parsing, key
derivation orchestration, and XTS chaining logic on top of it.

## Getting started

```csharp
using System.IO;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

// Password-only open: Asiri detects the encryption algorithm, hash algorithm, and
// filesystem type automatically, the same way VeraCrypt itself mounts a volume.
// OpenAsync returns an OpenResult - the container itself, plus which header region was
// actually used (see "Which header region" below) - rather than the container directly.
var container = (await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple")).Container;

try
{
    IDirectory root = container.Root;

    IFile file = await root.GetFileAsync("test.txt");
    string text = await file.ReadAllTextAsync();

    IDirectory data = await root.GetDirectoryAsync("data");
    foreach (IFileSystemEntry entry in await data.GetEntriesAsync())
    {
        System.Console.WriteLine(entry.Name);
    }
}
finally
{
    container.Close();
}
```

If you already know the encryption algorithm, the hash algorithm, or both, passing what you know
via `OpenOptions` narrows the search accordingly. The filesystem type has no equivalent option:
it's always detected directly from the decrypted volume's boot sector rather than searched for, so
there's nothing to narrow on that axis.

```csharp
// Known algorithm, unknown hash: only the hash algorithm is searched for.
var container = (await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple",
    new OpenOptions { Algorithm = CryptoAlgorithm.Aes })).Container;
```

`OpenOptions` also carries the PIM, keyfiles, and access mode - see below. Every I/O method is
`CancellationToken`-aware.

By default, `OpenAsync` tries the primary header and falls back to the backup header (VeraCrypt's
own recovery copy, near the end of the container file) if it fails validation. `OpenOptions.HeaderPreference`
can force one or the other explicitly instead - with no fallback to the other if that one fails -
for recovery or diagnostic purposes:

```csharp
// Use only the backup header - fails outright if it doesn't validate, rather than silently
// trying the primary instead.
var result = await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple",
    new OpenOptions { HeaderPreference = HeaderType.Backup });

// Which region was actually used is always available on the result - never HeaderType.Auto,
// regardless of what was requested. Kept off VeraCryptContainer itself, since it's a one-time
// fact about this OpenAsync call, not ongoing container state.
System.Console.WriteLine(result.HeaderType);
var container = result.Container;
```

## Creating a container

**⚠️ Container creation is pre-release. A container created this way has been confirmed to mount
and have its filesystem recognised by a real, running VeraCrypt — but only in one manual check, not
yet the exhaustive automated coverage read access has. See the caution earlier in this README.**

`CreateAsync` formats a brand new container file — fixed by `size`, its encryption algorithm, hash
algorithm, and filesystem type — and returns it already open, writable by default:

```csharp
using System.IO;
using uk.andyjohnson.Asiri.Core;

var container = (await VeraCryptContainer.CreateAsync(
    new FileInfo(@"C:\path\to\new-container.hc"),
    size: 64L * 1024 * 1024,
    password: "correct horse battery staple",
    CryptoAlgorithm.Aes,
    HashAlgorithm.Sha512,
    FileSystemType.Ntfs)).Container;

try
{
    // The new container is writable immediately - no separate step required.
    IFile file = await container.Root.CreateFileAsync("notes.txt");
}
finally
{
    container.Close();
}
```

`size` is the container's total file size, not the filesystem's — VeraCrypt reserves a fixed 256 KiB
for headers, and the filesystem gets whatever remains. `CreateOptions` carries the PIM, keyfiles, a
volume label, a cluster size (exFAT only), the access mode to open the new container with
(`ReadWrite` by default, unlike `OpenAsync`), and an `Overwrite` flag to replace an existing file at
the target path rather than reject the request. Only fixed-size containers are supported — Asiri
cannot grow or shrink one after creation.

## Writing to a container

**⚠️ Back up the container file before running this. Write access is pre-release and has not been
verified against real VeraCrypt — see the caution earlier in this README.**

Writing requires opening with `ContainerAccessMode.ReadWrite` - fixed for the container's whole
session, with no separate step to arm it afterward.

```csharp
using System.IO;
using System.Text;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

var container = (await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple",
    new OpenOptions { AccessMode = ContainerAccessMode.ReadWrite })).Container;

try
{
    IDirectory root = container.Root;

    IDirectory data = await root.CreateDirectoryAsync("data");
    IFile file = await data.CreateFileAsync("notes.txt");

    using (Stream stream = await file.OpenWriteAsync())
    {
        byte[] bytes = Encoding.UTF8.GetBytes("hello from Asiri");
        await stream.WriteAsync(bytes, 0, bytes.Length);
    }

    await file.RenameAsync("notes-renamed.txt");
}
finally
{
    container.Close();
}
```

Only fixed-size containers are supported — Asiri cannot grow or shrink a container's size.

## Changing a container's password or keyfiles

**⚠️ Back up the container file before running this. This is pre-release and has not been verified
against real VeraCrypt — see the caution earlier in this README. A bug here risks a worse outcome
than a filesystem write bug: the container could become permanently unopenable.**

Unlike the static method this used to be, `ChangeCredentialsAsync` is an instance method on a
container already open with `ContainerAccessMode.ReadWrite` — having opened it at all is itself the
proof of its current credentials, so only the new ones need supplying:

```csharp
using System.IO;
using uk.andyjohnson.Asiri.Core;

var container = (await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple",
    new OpenOptions { Algorithm = CryptoAlgorithm.Aes, HashAlgorithm = HashAlgorithm.Sha512, AccessMode = ContainerAccessMode.ReadWrite })).Container;

try
{
    await container.ChangeCredentialsAsync("a different correct horse battery staple");
}
finally
{
    container.Close();
}
```

The PIM and keyfiles can change independently of the password, and so can the hash algorithm, via
`ChangeCredentialsOptions`' optional `NewHashAlgorithm` — omit it to keep the current one. The
encryption algorithm itself is the one thing that can never change this way, matching VeraCrypt's
own behaviour: changing it would mean re-encrypting the entire data area, not just the header.

## Exporting a container's filesystem

`Asiri.Export` — a separate package from `Asiri.Core`, so its DiscUtils virtual-disk dependency
isn't forced on every `Asiri.Core` consumer — exports a container's decrypted filesystem to a real
disk image: none of it encrypted, and none of it interpreted by Asiri or DiscUtils on the way out.
Useful for handing the plaintext to a filesystem-checking tool, another person, a real OS's own
mount path, or a physical medium (flashing it to a USB drive, for example) entirely outside Asiri:

```csharp
using System.IO;
using uk.andyjohnson.Asiri.Core;
using uk.andyjohnson.Asiri.Export;

var container = (await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple",
    new OpenOptions { Algorithm = CryptoAlgorithm.Aes, HashAlgorithm = HashAlgorithm.Sha512 })).Container;

try
{
    using var destination = File.Create(@"C:\path\to\export.vhd");
    await new FileSystemExtractor(container).ExportAsync(
        destination, FileSystemExportFormat.Vhd, PartitionTableOption.SingleMbrPartition);
}
finally
{
    container.Close();
}
```

`FileSystemExportFormat` — the container format — and `PartitionTableOption` — whether a single MBR
partition wraps the result — are independent choices, so adding a new container format never doubles
the other. `FileSystemExportFormat` covers a bare raw image (a real, usable disk image in its own
right — what a tool like `dd`, or flashing to a USB drive, expects), VHD, VHDX, and VDI — Windows can
mount a VHD/VHDX natively, and VirtualBox a VDI, with no VeraCrypt or Asiri involved at all.
`PartitionTableOption.SingleMbrPartition` isn't supported alongside `RawImage` — there's no container
format there to wrap a partition table around.

## Repository structure

| Project | Purpose |
|---|---|
| [`Asiri.Abstractions`](Asiri.Abstractions) | Dependency-free filesystem contracts (`IDirectory`, `IFile`, `IFileSystemEntry`). Depends on nothing, so other software can target these interfaces without pulling in BouncyCastle or DiscUtils. |
| [`Asiri.Core`](Asiri.Core) | The library itself: VeraCrypt header parsing (`HeaderParser`), sector-level encryption and decryption (`SectorDecryptor`, `DecryptedBlockDeviceStream`), the cipher and hash implementations (under `Crypto/`), the DiscUtils-backed filesystem adapters (under `Filesystem/`), and the public entry point, `VeraCryptContainer`. |
| [`Asiri.Core.Tests`](Asiri.Core.Tests) | xUnit tests, run against real VeraCrypt container files checked into `Asiri.Core.Tests/Test Data` — covering every supported cipher/cascade, hash, filesystem, PIM, and keyfile combination — as well as synthetic, from-scratch header tests independent of the library's own crypto code, read-write tests covering create/delete/rename/move/attributes/timestamps across all three filesystems, and password/keyfile-change tests. |
| [`Asiri.Export`](Asiri.Export) | Exports a container's decrypted filesystem to a real disk image (a bare raw image, or VHD/VHDX/VDI, with or without a partition table). Kept separate from `Asiri.Core` so its DiscUtils virtual-disk dependencies aren't forced on every `Asiri.Core` consumer. |
| [`Asiri.Export.Tests`](Asiri.Export.Tests) | xUnit tests for `Asiri.Export`, run against the same real VeraCrypt containers as `Asiri.Core.Tests`. |
| [`Asiri.ContainerBrowser`](Asiri.ContainerBrowser) | A small WPF reference application: open a container read-only or with write access, browse and edit its folder tree (create/rename/move/delete, drag-and-drop import/export), change its password, keyfiles, PIM, or hash algorithm, export its filesystem to a disk image, and view text files, images, or a hex dump of anything else. Demonstrates `Asiri.Core` as a consumer would use it. |
| [`Asiri.Diagnostics`](Asiri.Diagnostics) | A standalone command-line tool, not part of the library or its public API: compares what `Asiri.Core` decrypts from a container's data area against what a real, already-mounted VeraCrypt exposes for the same container, to isolate whether a filesystem-recognition failure is a decryption mismatch or something downstream of decryption; also a cheap boot-sector-only export. |

Each project has its own `AGENT.md` describing the scope and conventions the agent worked to.

## Acknowledgements

- [VeraCrypt](https://veracrypt.io/) — the encryption software whose container format Asiri reads.
  Asiri is an independent, unofficial implementation and is not affiliated with the VeraCrypt
  project. See the [VeraCrypt technical documentation](https://veracrypt.io/en/Technical%20Details.html)
  for the volume format this project implements against.
- [BouncyCastle](https://github.com/bcgit/bc-csharp) — the cryptographic primitives (block ciphers,
  digests, PBKDF2) that Asiri builds VeraCrypt's key derivation and XTS mode on top of.
- [DiscUtils](https://github.com/LTRData/DiscUtils) (LTRData fork) — the NTFS, FAT, and exFAT
  filesystem readers Asiri points at its decrypted volume stream.
- [SharpVectors](https://github.com/ElinamLLC/SharpVectors) — SVG icon rendering used by
  `Asiri.ContainerBrowser` only.

## License

MIT — see [LICENSE.md](LICENSE.md), which also lists the licenses of the third-party packages
Asiri depends on.
