# Asiri

Asiri provides standalone, read-only access to [VeraCrypt](https://veracrypt.io/) encrypted file
containers from .NET, without depending on the VeraCrypt application itself. Given a container file
and its password, it derives the keys, decrypts the volume header, and exposes the container's
filesystem — files and directories — through a small, dependency-free abstraction that a consuming
application can browse or read from directly.

"Asiri" is the Swahili word for "secret".

## ⚠️ This code is agent-written

Every line of code, test, and piece of documentation in this repository was written by
**Claude Sonnet 5** (Anthropic), acting as a coding agent inside Claude Code, working from
instructions given by **Andrew Johnson** ([andy@andyjohnson.uk](mailto:andy@andyjohnson.uk),
[andyjohnson.uk](https://andyjohnson.uk)), who prompted, reviewed, and directed the work.

This is a hobby/experimental project exploring what an AI coding agent can produce end-to-end. It
has **not** undergone independent security review or a cryptographic audit. It implements read-only
container access only — it will never write to a container — but you should treat it accordingly:
do not use it as your only means of accessing data you care about, and do not rely on it in any
security-critical context without your own review.

One thing that is independent of the agent: every real VeraCrypt container in
`Asiri.Core.Tests/Test Data` was created using the actual VeraCrypt application, by Andrew, not
generated or shaped by the agent. The agent never had the ability to make a test container's
ciphertext agree with its own understanding of the format. As a result, mutating any test
container's bytes and re-running the test suite will produce failures — a simple, independent check
that the tests are exercising real decryption against real VeraCrypt output, not just checking the
code's assumptions against themselves.

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

**Not supported, by design:**
- Writing to a container — Asiri is read-only.
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

If you already know the container's algorithm, hash, and filesystem type, an overload of
`OpenAsync` accepts them explicitly and skips the detection step. Every I/O method is
`CancellationToken`-aware.

## Repository structure

| Project | Purpose |
|---|---|
| [`Asiri.Abstractions`](Asiri.Abstractions) | Dependency-free filesystem contracts (`IDirectory`, `IFile`, `IFileSystemEntry`). Depends on nothing, so other software can target these interfaces without pulling in BouncyCastle or DiscUtils. |
| [`Asiri.Core`](Asiri.Core) | The library itself: VeraCrypt header parsing (`HeaderParser`), sector-level decryption (`SectorDecryptor`, `DecryptedBlockDeviceStream`), the cipher and hash implementations (under `Crypto/`), the DiscUtils-backed filesystem adapters (under `Filesystem/`), and the public entry point, `VeraCryptContainer`. |
| [`Asiri.Core.Tests`](Asiri.Core.Tests) | xUnit tests, run against real VeraCrypt container files checked into `Asiri.Core.Tests/Test Data` — covering every supported cipher/cascade, hash, filesystem, PIM, and keyfile combination — as well as synthetic, from-scratch header tests independent of the library's own crypto code. |
| [`Asiri.ContainerBrowser`](Asiri.ContainerBrowser) | A small WPF reference application: open a container, browse its folder tree, and view text files, images, or a hex dump of anything else. Demonstrates `Asiri.Core` as a consumer would use it. |

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
