<img src="assets/pointsman.png" width="96" alt="">

# Pointsman

Choose which network adapter each Windows application uses.

Windows routes by destination address, not by application: every program on the
machine shares one default route. Pointsman adds the missing dimension — pick
an adapter per app in a list, and that app's traffic leaves through it. The app
itself needs no configuration and cannot tell the difference.

## What it does

- Lists your adapters — Ethernet, Wi-Fi, and VPN tunnels alike — with their
  current address and state.
- Lists the processes actually worth routing: anything with a window, plus
  anything holding a socket, because the process doing the networking is often
  not the one with the window (Steam downloads through a windowless
  `steam.exe`).
- Applies a rule to the helper processes an app spawns, so a rule set on a
  browser or a game launcher covers the children it starts.
- Picks up rule changes immediately — no restart.
- Says so when a rule cannot currently apply, rather than letting traffic
  quietly fall back to the default route.

## How it works

There is no per-app routing in Windows, and no way to redirect a connection
from user mode alone. Pointsman uses [WinDivert](https://github.com/basil00/WinDivert),
a pre-signed kernel driver, to do two things a user-mode program cannot:

1. **Attribute a flow.** WinDivert's socket layer reports the process behind
   every new connection, so a packet can be traced to the program that sent it.
2. **Redirect it.** The packet is rewritten to a loopback address and handed to
   a local relay, which opens the outbound connection with its socket bound to
   the chosen adapter's address. Windows' own TCP/IP stack carries both halves.

```
App (unmodified)
  │  connect() → 1.2.3.4:443
  ▼
Redirector  ── identifies the process, rewrites the destination to 127.0.0.1
  ▼
Local relay ── binds its outbound socket to the chosen adapter
  ▼
Ethernet / Wi-Fi / VPN adapter → internet
```

TCP and UDP are both handled, so QUIC follows its app's adapter along with
everything else.

## Requirements

- Windows 10 or 11, 64-bit
- Administrator rights — loading the driver requires them
- .NET 9 Desktop Runtime, unless you use a self-contained build

## Installing

Download from the [releases page](https://github.com/pooriaanv/Pointsman/releases).
Two forms of the same build are published:

- `Pointsman-<version>-setup.exe` — installer; adds shortcuts and cleans up
  after itself when uninstalled.
- `Pointsman-<version>-win-x64-portable.zip` — extract anywhere and run.

Both are self-contained, so no .NET runtime needs to be installed first.

Neither is code-signed, so Windows will show a SmartScreen warning the first
time you run it — choose **More info → Run anyway**. `SHA256SUMS.txt` is
published beside the downloads if you want to check what you got:

```bash
Get-FileHash .\Pointsman-0.1.0-setup.exe -Algorithm SHA256
```

The kernel driver itself *is* signed, by the WinDivert authors, and is shipped
exactly as they published it.

Some antivirus products flag WinDivert as riskware, under names like `HackTool`
or `RiskWare.WinDivert`. This is not a detection of anything Pointsman does: the
driver can capture and modify packets, which is a capability worth flagging in
the abstract and is also the only way per-app routing can work at all. Firewalls,
VPN clients and packet analysers that use the same driver draw the same warnings.
Nothing here disables or evades that check — if your antivirus blocks it, that is
its call to make, and yours to override knowingly.

## Updating

Download the new installer and run it; it upgrades in place. It closes Pointsman
if it is running, unloads the driver, replaces the files and leaves your rules
untouched. There is no need to uninstall first.

For the portable build, close Pointsman and replace the folder. Rules live
outside it and survive.

## Building

```
dotnet build -c Release
```

The WinDivert driver and its DLL are copied next to the executable; the driver
is loaded from that directory, so keep them together.

To produce the release artifacts locally, publish and then run
[Inno Setup](https://jrsoftware.org/isinfo.php) over the result:

```
dotnet publish src/Pointsman.App/Pointsman.App.csproj -c Release -r win-x64 --self-contained true -o publish
ISCC.exe /DAppVersion=0.1.0 installer\Pointsman.iss
```

Pushing a `v*` tag does the same thing on CI and attaches the output to a
GitHub release.

## Known limitations

These are properties of how Windows works, not bugs waiting to be fixed:

- **DNS cannot be routed per app.** Windows resolves names through the
  `Dnscache` service, so queries leave the machine from `svchost.exe` and carry
  no trace of which program asked. A rule moves an app's connections, not its
  lookups.
- **VPNs that tunnel in kernel mode cannot be targeted.** Pointsman sees a
  flow when a process opens a socket. A client whose tunnel is built by a
  filter driver never opens one, so no rule can reach it.
- **IPv6 is blocked, not routed.** When a ruled app tries to reach a global
  IPv6 address it is stopped rather than allowed out on the wrong adapter,
  since letting it through would defeat the rule. This path is untested against
  a real IPv6 network.
- **Throughput has a ceiling.** Every outbound TCP and UDP packet crosses into
  user mode through a single loop, and ruled traffic is copied twice more. Fine
  for ordinary use; not a line-rate router.
- **An app can only use an adapter that works.** Routing a program to a link
  where its servers are unreachable makes it fail — correctly, but the app will
  simply look broken.

## Uninstalling

If you used the installer, uninstall from Windows Settings as usual. It closes
Pointsman if it is running, removes the driver service, and asks whether to
keep your rules — answering No keeps them for a future reinstall.

The portable build has no uninstaller: delete the folder. WinDivert registers a
kernel service while Pointsman runs and removes it on exit, but a process that
was killed rather than closed never gets that far, so check for a leftover:

```bash
sc.exe query WinDivert
```

If it is still there, remove it with `sc.exe stop WinDivert` followed by
`sc.exe delete WinDivert`, from an administrator prompt.

Rules live in `%AppData%\Pointsman\rules.json` either way, and are never
removed unless you ask for it.

## License

GPL version 3 — see [LICENSE](LICENSE).

Bundled third-party components and their terms are listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
