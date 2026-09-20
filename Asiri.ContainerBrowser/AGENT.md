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
- If the container was opened with write access, provide a way to arm/disarm actual writing
  (`VeraCryptContainer.IsWritable`) for the remainder of the session - it cannot be armed at all if
  the container wasn't opened with write access, since that ceiling can't be raised without
  reopening the container.
- When writing is armed, provide, via a context menu on tree items:
  - On a directory: create a subdirectory, create an empty file, rename, delete (recursive if
    non-empty, after confirmation), move to another directory anywhere in the container, paste
    file(s) from the clipboard, and edit attributes/timestamps.
  - On a file: rename, delete, move to another directory, and edit attributes/timestamps.
  - All of the above confirm before a destructive action (delete, or overwriting an existing entry).
- Support importing external files into a container directory via clipboard paste and via
  drag-and-drop from outside the app; support moving an item within the container via drag-and-drop
  onto another directory in the tree.
- Support dragging a file out of the tree to export a decrypted copy to another application (e.g.
  Explorer) - this is a read operation, so it doesn't require writing to be armed, unlike moving a
  file or directory within the container, which does.
- Provide a way to create a brand new VeraCrypt container via `VeraCryptContainer.CreateAsync`, using
  `NewContainerDialog` for its path (via a Browse... button opening a file save dialog), size,
  filesystem type, an optional cluster size, an optional volume label, the password, PIM, keyfiles,
  and the encryption/hash algorithm to protect it with - the algorithm/hash choices are required
  explicitly, the same way the "current credentials" step of the Change Password flow requires them,
  since creation has no auto-detecting overload to fall back on. The cluster size field is only
  enabled when exFAT is selected, since `CreateAsync` rejects a non-default cluster size for NTFS/FAT
  outright (see Asiri.Core's own scope notes). While creation is in progress, show `ProgressDialog`,
  the same as Open. On success, load the new (empty) container into the window exactly as Open would,
  with writing already armed - there is no reason to make the user separately enable it before
  populating a container they just created.
- Provide a way to export the currently open container's decrypted filesystem to a plain file via
  `VeraCryptContainer.DumpRawImageAsync`, using `DumpImageDialog` for the output path (via a
  Browse... button, matching `NewContainerDialog`'s own pattern) and a picker for the
  `RawImageExportFormat` to export as (whole filesystem, boot sector only, an unpartitioned VHD, or a
  VHD with a single MBR partition). Enabled only while a container is open, alongside Close. Show
  `ProgressDialog` while the export is in progress, the same as every other potentially slow
  operation.
- Provide a way to change a container's password, keyfiles, PIM, and/or hash algorithm via
  `VeraCryptContainer.ChangePasswordAsync`, as its own command independent of whatever container (if
  any) is currently open in the window - that method is static and operates on a file the user picks
  fresh each time, since it never needs a container mounted at all. Since that method has no
  auto-detecting overload, prompt for the current encryption and hash algorithm explicitly rather
  than treating them as optional the way the ordinary Open flow does.
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
