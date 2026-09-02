# Third-party notices

Pointsman is distributed with the components below. Each is used unmodified
and linked dynamically; none of Pointsman's own source is derived from them.

## WinDivert 2.2.2

- Files: `WinDivert.dll`, `WinDivert64.sys`
- Copyright (c) Basil Fierz and contributors
- Source: https://github.com/basil00/WinDivert
- License: dual-licensed under your choice of GNU Lesser General Public
  License version 3, or GNU General Public License version 2.

The kernel driver `WinDivert64.sys` is redistributed exactly as published by
its authors, including their code signature. Pointsman neither modifies nor
re-signs it.

## SharpDivert 1.1.0

- Managed bindings for WinDivert, obtained from NuGet
- Source: https://github.com/gcrtnst/SharpDivert
- License: dual-licensed under your choice of GNU Lesser General Public
  License version 3, or GNU General Public License version 2.

## Relationship to Pointsman's own license

Pointsman is licensed under GPL version 3 (see `LICENSE`). Both components
above are available under LGPLv3, which permits use from a GPLv3 work, so the
combination is distributable. Their own terms continue to govern them: if you
redistribute Pointsman, keep this file and the notices it points to.

To obtain the source of either component, follow the links above; both are
published by their authors and are not modified here.
