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
mature, well-exercised path; write access exists but is newer, opt-in, and has not yet been verified
against real VeraCrypt (only against Asiri's own round-trip and synthetic tests — see below). Treat
the whole library accordingly: do not use it as your only means of accessing data you care about, and
do not rely on it in any security-critical context without your own review.

**⚠️ Write access is pre-release and unverified against real VeraCrypt. Only use it on containers you
have backed up.** A bug in the write path could corrupt a container beyond what VeraCrypt itself can
open. Read access does not carry this risk.

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

Write access does not yet have an equivalent independent check: its tests confirm that Asiri's own
encryption and decryption agree with each other (self-consistency), not that a container Asiri wrote
to is still readable by real VeraCrypt. That verification is planned but not yet done — see the
caution above. The same applies to changing a container's password or keyfiles.

## Status

Pre-release, version `0.2.0`. The public API may still change.

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
`ContainerAccessMode.ReadWrite` and then explicitly setting `IsWritable = true` enables creating,
deleting, renaming, and moving files and directories, setting attributes and timestamps, and writing
file content via `IFile.OpenWriteAsync()`. Both the access mode (checked at open time) and
`IsWritable` (checked per-operation, and can be turned back off) must agree for a write to be
allowed — this two-key gate is deliberate, so that opening a container for potential writing doesn't
by itself put it at risk. Only fixed-size containers are supported for writing: Asiri cannot grow or
shrink a container, so operations that would change its size beyond its existing free space behave
the same as they would on a full disk.

**Changing a password, keyfiles, PIM, and/or hash algorithm** (opt-in, pre-release — see the caution
above): `VeraCryptContainer.ChangePasswordAsync` rewrites a container's volume header — both the
primary and backup copies, each with its own independent random salt — under a freshly derived key,
without touching the container's contents: the master and secondary keys that actually protect the
data are never changed. Verified against VeraCrypt's own source, not just its documentation. Static,
and doesn't require the container to be open first, since this never reaches the filesystem region
at all. Two scope reductions relative to real VeraCrypt, both deliberate: no multi-pass anti-forensic
overwrite of the old header location (VeraCrypt's own optional defense against recovering it via
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
var container = await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple");

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
narrows the search accordingly. The filesystem type has no equivalent parameter: it's always
detected directly from the decrypted volume's boot sector rather than searched for, so there's
nothing to narrow on that axis.

```csharp
// Known algorithm, unknown hash: only the hash algorithm is searched for.
var container = await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple",
    algo: CryptoAlgorithm.Aes);
```

And if you already know the container's algorithm, hash, and filesystem type, a fully explicit
overload of `OpenAsync` accepts all three and skips detection entirely. Every I/O method is
`CancellationToken`-aware.

## Writing to a container

**⚠️ Back up the container file before running this. Write access is pre-release and has not been
verified against real VeraCrypt — see the caution earlier in this README.**

Writing requires two things: opening with `ContainerAccessMode.ReadWrite`, and then explicitly
arming `IsWritable`. Either alone is not enough — this is intentional, so that code paths which
merely *open* a container can't accidentally write to it.

```csharp
using System.IO;
using System.Text;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

var container = await VeraCryptContainer.OpenAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    password: "correct horse battery staple",
    accessMode: ContainerAccessMode.ReadWrite);

container.IsWritable = true;

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

Unlike opening or writing to a container, this doesn't need the container to already be open —
`ChangePasswordAsync` is static, and operates directly on the file:

```csharp
using System.IO;
using uk.andyjohnson.Asiri.Core;

await VeraCryptContainer.ChangePasswordAsync(
    new FileInfo(@"C:\path\to\container.hc"),
    oldPassword: "correct horse battery staple",
    algorithm: CryptoAlgorithm.Aes,
    oldHashAlgorithm: HashAlgorithm.Sha512,
    oldPim: 0,
    oldKeyFiles: null,
    newPassword: "a different correct horse battery staple",
    newPim: 0,
    newKeyFiles: null);
```

The encryption algorithm must be known and stated explicitly — unlike `OpenAsync`, there is no
auto-detecting overload here, since this is a destructive operation and shouldn't invite a slow
brute-force guess before it runs. The PIM and keyfiles can change independently of the password, and
so can the hash algorithm, via an optional `newHashAlgorithm` parameter — omit it to keep the current
one. The encryption algorithm itself is the one thing that can never change this way, matching
VeraCrypt's own behaviour: changing it would mean re-encrypting the entire data area, not just the
header.

## Repository structure

| Project | Purpose |
|---|---|
| [`Asiri.Abstractions`](Asiri.Abstractions) | Dependency-free filesystem contracts (`IDirectory`, `IFile`, `IFileSystemEntry`). Depends on nothing, so other software can target these interfaces without pulling in BouncyCastle or DiscUtils. |
| [`Asiri.Core`](Asiri.Core) | The library itself: VeraCrypt header parsing (`HeaderParser`), sector-level encryption and decryption (`SectorDecryptor`, `DecryptedBlockDeviceStream`), the cipher and hash implementations (under `Crypto/`), the DiscUtils-backed filesystem adapters (under `Filesystem/`), and the public entry point, `VeraCryptContainer`. |
| [`Asiri.Core.Tests`](Asiri.Core.Tests) | xUnit tests, run against real VeraCrypt container files checked into `Asiri.Core.Tests/Test Data` — covering every supported cipher/cascade, hash, filesystem, PIM, and keyfile combination — as well as synthetic, from-scratch header tests independent of the library's own crypto code, read-write tests covering create/delete/rename/move/attributes/timestamps across all three filesystems, and password/keyfile-change tests. |
| [`Asiri.ContainerBrowser`](Asiri.ContainerBrowser) | A small WPF reference application: open a container read-only or with write access, browse and edit its folder tree (create/rename/move/delete, drag-and-drop import/export), change its password, keyfiles, PIM, or hash algorithm, and view text files, images, or a hex dump of anything else. Demonstrates `Asiri.Core` as a consumer would use it. |

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
