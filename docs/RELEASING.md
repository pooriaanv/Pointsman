# Releasing Pointsman

Releases are built by [release.yml](../.github/workflows/release.yml) when a `v*` tag is
pushed. You never build or upload release files by hand; the workflow publishes the installer,
the portable zip and `SHA256SUMS.txt` to a GitHub release.

Every installed copy of Pointsman checks
`https://api.github.com/repos/pooriaanv/Pointsman/releases/latest`, so **publishing a release
means every user hears about it**. Read this before you tag.

## Normal release

```bash
git tag -a v0.2.0 -m "Pointsman 0.2.0"
git push origin v0.2.0
```

What users see: a notification in the app saying the new version is available, with an
**Update** button. Nothing installs unless they click it, or unless they turned on
*Download and install updates automatically* in Settings, which is off by default.

## Critical release

A critical release **is installed on every machine without asking**, even where automatic
updates are turned off. Pointsman downloads it, checks its checksum, closes itself, runs the
installer silently and starts again.

Use it only for fixes people must not go without:

- a security problem
- a bug that leaks traffic out of the wrong adapter, i.e. a rule that silently stops working
- a bug that breaks networking on the machine, or leaves the driver in a bad state

Do **not** use it for features, UI changes or ordinary bug fixes. Installing without asking
spends users' trust; spend it rarely.

### How to mark a release critical

Put `[critical]` in the **tag message**:

```bash
git tag -a v0.2.1 -m "[critical] Stop UDP leaking to the default route when an adapter drops"
git push origin v0.2.1
```

Two things to remember:

- **It must be an annotated tag (`-a`).** A plain `git tag v0.2.1` has no message, so the
  release comes out normal.
- `[critical]` can go anywhere in the message, in any case.

The workflow sees `[critical]` and adds this line to the release notes:

```
<!-- pointsman:critical -->
```

That line is the actual switch. It is an HTML comment, so it does not show on the release
page. The app reads it from the release notes; it never sees the tag.

### Check it worked

After the workflow finishes:

```bash
gh release view v0.2.1 --json body --jq .body
```

The output must contain `<!-- pointsman:critical -->`. If it doesn't, the release went out
as normal. Mark it by hand as described next.

### Marking or unmarking an existing release

Because the switch is just that line in the release notes, you can change it after
publishing. Edit the release on GitHub, or:

```bash
gh release view v0.2.1 --json body --jq .body > notes.md
# add or remove the line <!-- pointsman:critical --> in notes.md
gh release edit v0.2.1 --notes-file notes.md
```

Clients pick up the change on their next check (at startup, then every few hours). A
machine that already installed the release is unaffected either way.

### What a critical release still cannot do

- **Portable copies are never updated automatically.** There is no installer to run, so they
  only get the notification. If the fix matters enough, say so in the release notes.
- **Only the latest release counts.** Clients look at `releases/latest` only. If you publish
  a critical 0.2.1 and then a normal 0.2.2 before everyone has updated, those who missed 0.2.1
  are just *notified* about 0.2.2. If 0.2.2 contains the critical fix too, mark it critical as
  well.
- **The release must have its installer and `SHA256SUMS.txt`.** The app refuses to run an
  installer it cannot verify, critical or not. The workflow attaches both; don't delete them
  from the release.
- **Pre-releases are invisible.** `releases/latest` skips them, so a `-beta` tag never reaches
  users, critical or not.

## Testing an update before tagging

A local build is version `0.0.0-dev` and never checks for updates. To pretend to be an old
release, so that it finds the current one:

```bash
$env:POINTSMAN_UPDATE_TEST_VERSION = "0.1.0"
.\Pointsman.exe
```

This tests against the real latest release on GitHub, so it can only show behaviour for a
release that is already published.
