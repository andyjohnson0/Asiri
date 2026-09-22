# Asiri.ContainerBrowser – Agent Instructions

This document takes precedence over all other instructions for the Asiri.ContainerBrowser project.

## Scope
- Implement a WPF app that provides read and write access to VeraCrypt encrypted file containers
  using Asiri.Core.
- Build on the provided `Asiri.ContainerBrowser` project.
- Use only Asiri.Core (and its Asiri.Abstractions dependency) for VeraCrypt container access.
- Classic two pane app. Left pane is a tree view of folders and files. Right shows contents of selected file.
- Provide a way to open a VeraCrypt container using a file open dialog. Then prompt for the
  container's credentials - password, optional PIM, optional keyfiles, optionally the encryption
  algorithm and/or hash algorithm if already known (narrows Asiri.Core's search accordingly instead
  of it trying every combination), and whether to open with write access (off by default) - via
  `CredentialsDialog`. While the open is in progress, show `ProgressDialog`: an indeterminate
  progress indicator with a Cancel button that requests cancellation via the `CancellationToken`
  passed to `OpenAsync`. Then display the container's folder hierarchy.
- When a file is clicked on:
  - If an image (jpeg or png) then display image in right-hand pane.
  - If a txt file then display text in right-hand pane.
  - Otherwise display hex dump of file contents in right-hand pane.
- Whether writing is permitted is fixed for the whole session by `VeraCryptContainer.AccessMode`,
  set when the container was opened - there is no runtime arm/disarm toggle to build a UI for, and
  no way to raise it without closing and reopening the container.
- When the container is open for writing (`AccessMode == ContainerAccessMode.ReadWrite`), provide,
  via a context menu on tree items:
  - On a directory: create a subdirectory, create an empty file, rename, delete (recursive if
    non-empty, after confirmation), move to another directory anywhere in the container, paste
    file(s) from the clipboard, and edit attributes/timestamps.
  - On a file: rename, delete, move to another directory, and edit attributes/timestamps.
  - All of the above confirm before a destructive action (delete, or overwriting an existing entry).
- Support importing external files into a container directory via clipboard paste and via
  drag-and-drop from outside the app; support moving an item within the container via drag-and-drop
  onto another directory in the tree.
- Support dragging a file out of the tree to export a decrypted copy to another application (e.g.
  Explorer) - this is a read operation, so it's available regardless of `AccessMode`, unlike moving
  a file or directory within the container, which requires write access.
- Provide a way to create a brand new VeraCrypt container via `VeraCryptContainer.CreateAsync`, using
  `NewContainerDialog` for its path (via a Browse... button opening a file save dialog), size,
  filesystem type, an optional cluster size, an optional volume label, whether to enable write
  access (a checkbox defaulting to checked, matching `CreateOptions.AccessMode`'s own default - a
  container you just created is, in every realistic case, about to be populated immediately), the
  password, PIM, keyfiles, and the encryption/hash algorithm to protect it with - the algorithm/hash
  choices are required explicitly (unlike `CredentialsDialog`'s own "Unspecified" option for the
  ordinary Open flow), since creation has no auto-detecting overload to fall back on. The cluster
  size field is only enabled when exFAT is selected, since
  `CreateAsync` rejects a non-default cluster size for NTFS/FAT outright (see Asiri.Core's own scope
  notes). Passes `Overwrite = true` (the file save dialog's own standard "replace it?" prompt already
  confirmed this, so `CreateAsync` should honour it rather than rejecting the request a second time).
  While creation is in progress, show `ProgressDialog`, the same as Open. On success, load the new
  (empty) container into the window exactly as Open would.
- Provide a way to export the currently open container's decrypted filesystem to a plain file via
  `Asiri.Export`'s `FileSystemExtractor.ExportAsync`, using `DumpImageDialog` for the output path
  (via a Browse... button, matching `NewContainerDialog`'s own pattern) and a picker for the
  `FileSystemExportFormat` to export as (a raw image, an unpartitioned VHD, or a VHD with a single
  MBR partition - boot-sector-only export is diagnostic-only and lives in `Asiri.Diagnostics`
  instead, not offered here). Enabled only while a container is open, alongside Close. Show
  `ProgressDialog` while the export is in progress, the same as every other potentially slow
  operation.
- Provide a way to change the currently open container's password, keyfiles, PIM, and/or hash
  algorithm via `VeraCryptContainer.ChangeCredentialsAsync` - an instance method requiring
  `ContainerAccessMode.ReadWrite`, so the command is only enabled while such a container is open;
  unlike the static method it replaced, there is no separate "current credentials" step, since
  having opened the container at all is itself the proof of those. Only prompt for the new
  credentials, via `ChangeCredentialsDialog`.
- Provide a way to close the VeraCrypt container.
- Use bootstrap svg icons if necessary. I've added a dependency on SharpVectors.Wpf - use it if you want.
- Do not implement unneccessary functionality not described here.
- Do not implement tests.
- Do not modify the core library.
- Do not add other projects without being explicitly asked to.

## Coding Conventions
- Follow .NET naming conventions:
  - PascalCase for classes, methods, constants
  - camelCase for locals and parameters
  - Member variables prefixed with `_`
- Use minimal in‑code comments.
- Use async where appropriate.
