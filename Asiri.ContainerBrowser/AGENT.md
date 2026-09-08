# Asiri.ContainerBrowser – Agent Instructions

This document takes precedence over all other instructions for the Asiri.ContainerBrowser project.

## Scope
- Implement a WPF app that provides read‑only access to VeraCrypt encrypted file containers using Asiri.Core.
- Build on the provided `Asiri.ContainerBrowser` project.
- Use only Asiri.Core (and its Asiri.Abstractions dependency) for VeraCrypt container access.
- Classic two pane app. Left pane is a tree view of folders and files. Right shows contents of selected file.
- Provide a way to open a VeraCrypt container using a file open dialog. Then prompt for the
  container's credentials - password, optional PIM, optional keyfiles - via `CredentialsDialog`.
  Then display the container's folder hierarchy.
- When a file is clicked on:
  - If an image (jpeg or png) then display image in right-hand pane.
  - If a txt file then display text in right-hand pane.
  - Otherwise display hex dump of file contents in right-hand pane.
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
