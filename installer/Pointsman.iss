; Inno Setup script for Pointsman.
;
; Build with:  ISCC.exe /DAppVersion=0.1.0 installer\Pointsman.iss
; It packages whatever is in publish\, so run the publish step first:
;   dotnet publish src\Pointsman.App\Pointsman.App.csproj -c Release -r win-x64 --self-contained true -o publish

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif

#define AppName    "Pointsman"
#define AppExeName "Pointsman.exe"
#define AppUrl     "https://github.com/pooriaanv/Pointsman"

[Setup]
; Never change AppId: it is how Windows recognises an existing install and
; upgrades it in place instead of leaving two copies behind.
AppId={{621860AD-FB44-489D-88D4-7BB70B24B8D7}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=Pointsman-{#AppVersion}-setup
UninstallDisplayIcon={app}\{#AppExeName}
SetupIconFile=..\src\Pointsman.App\Resources\pointsman.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

; The app loads a kernel driver, which needs administrator rights, and it
; installs to Program Files. Both rule out a per-user install.
PrivilegesRequired=admin

; 64-bit only: the bundled driver is WinDivert64.sys and the app targets x64.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Pointsman holds its own executable and the driver open while running, so
; ask Restart Manager to close it rather than failing on a locked file. Closing
; it also lets it unregister the driver service on its own way out.
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; WinDivert.dll and WinDivert64.sys have to stay beside the executable — the
; driver is registered from the path it is found at, not from a system folder.
Source: "..\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; shellexec is required, not cosmetic. Setup runs the finish-page launch as the
; original user rather than as itself, so that installing something does not
; leave it running as administrator. Pointsman asks for administrator in its
; manifest, and CreateProcess — which is what Setup uses without this flag —
; cannot raise a UAC prompt; it just fails with "The requested operation
; requires elevation", error 740, which is what ticking the box produced.
; ShellExecuteEx reads the manifest and asks properly.
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; WinDivert registers its driver as a service on first use and removes it when
; the last handle closes. If Pointsman was killed rather than closed, that
; cleanup never ran and the service is left registered — pointing at files this
; uninstaller is about to delete. Remove it here so nothing is left behind.
; Both commands fail harmlessly when the service is already gone, which is the
; normal case after a clean exit.
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert"; Flags: runhidden; RunOnceId: "StopWinDivertService"
Filename: "{sys}\sc.exe"; Parameters: "delete WinDivert"; Flags: runhidden; RunOnceId: "DeleteWinDivertService"

[UninstallDelete]
; Every file goes, but the folder itself was still left behind in Program
; Files, with nothing scheduled to remove it later. The uninstaller runs from
; inside it, so say explicitly that it should go once it is empty.
Type: dirifempty; Name: "{app}"

[Code]
// Close Pointsman before touching its files.
//
// CloseApplications=yes is supposed to arrange this through Restart Manager,
// but on an uninstall it did nothing at all — no Restart Manager activity in
// the log — and 79 files stayed behind, held open by the running process,
// while the uninstaller still reported success. Do it explicitly instead of
// trusting a mechanism that fails silently.
procedure CloseRunningApp;
var
  ResultCode: Integer;
begin
  // Ask first: taskkill without /F posts WM_CLOSE, which lets Pointsman shut
  // down properly and unregister the driver on its own — cleaner than stopping
  // the service out from under it. /F is the fallback for a hung window.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM Pointsman.exe',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(3000);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Pointsman.exe',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
end;

// Stopping the driver service is what makes an upgrade possible at all.
//
// Closing Pointsman by force skips the cleanup that would have unregistered
// the driver, so WinDivert stays loaded and the kernel keeps WinDivert64.sys
// open. Setup then cannot replace that file — "DeleteFile failed; code 5.
// Access is denied." — and rolls the whole install back. Every upgrade over a
// running install failed this way until the service was stopped here first.
procedure StopDriverService;
var
  ResultCode: Integer;
begin
  // Both fail harmlessly when the service was never registered, which is the
  // normal case on a first install and after a clean exit.
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete WinDivert', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // sc returns as soon as the service manager accepts the request; the kernel
  // releases the driver file a moment later. Without this pause the next step
  // can still find it locked.
  Sleep(2000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  CloseRunningApp;
  StopDriverService;
  Result := '';
end;

// The earliest hook an uninstall offers, so the app is gone before
// [UninstallRun] asks the service manager to remove the driver: the service
// cannot stop while Pointsman still holds a handle to it, and it sat in
// StopPending until the process went away.
function InitializeUninstall: Boolean;
begin
  CloseRunningApp;
  Result := True;
end;

// Rules are the user's own data, not part of the program, so they survive an
// uninstall unless the user says otherwise — reinstalling should not silently
// lose every adapter assignment they made.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  RulesDir: String;
begin
  // [UninstallRun] has already asked the service manager to remove the driver
  // by this point, but the kernel may not have let go of WinDivert64.sys yet,
  // and files are deleted right after this returns. Give it the same moment the
  // install path gets.
  if CurUninstallStep = usUninstall then
    Sleep(2000);

  if CurUninstallStep = usPostUninstall then
  begin
    RulesDir := ExpandConstant('{userappdata}\Pointsman');
    if DirExists(RulesDir) then
    begin
      // SuppressibleMsgBox, not MsgBox: a plain MsgBox is shown even under
      // /VERYSILENT, so an unattended uninstall would sit waiting for an answer
      // nobody is there to give. This one answers itself with IDNO when message
      // boxes are suppressed, which is also the safe answer — silence must not
      // cost the user their rules.
      if SuppressibleMsgBox('Also delete your saved adapter rules?' + #13#10 + #13#10
                            + RulesDir + #13#10 + #13#10
                            + 'Choose No to keep them for a future reinstall.',
                            mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
        DelTree(RulesDir, True, True, True);
    end;
  end;
end;
