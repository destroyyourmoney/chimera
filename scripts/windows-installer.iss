; Inno Setup script for CHIMERA's Windows installer.
;
; Packages the flat chimera_tray\ folder (produced by build-app-windows.ps1:
; chimera_tray.exe, chimera.dll, chimera.exe, chimera-helper.exe, wintun.dll,
; flutter_windows.dll, data\, vc_redist.x64.exe, plugin DLLs) into a single
; setup .exe that:
;   1. installs the VC++ runtime silently (fixes the "MSVCP140.dll was not
;      found" error on clean machines -- see build-app-windows.ps1's comment
;      on why the runtime isn't bundled directly),
;   2. copies everything into Program Files,
;   3. registers + starts the ChimeraNetHelper Windows service by running
;      chimera-helper.exe install (see cmd/chimera-helper/admin_windows.go),
;   4. creates Start Menu / optional desktop shortcuts for the tray app,
;   5. on uninstall: restores OS networking, stops/removes the service, kills
;      any still-running chimera process (so Windows can actually delete the
;      locked .exe/.dll files instead of silently leaving {app} behind with
;      chimera_tray.exe still running -- see [UninstallRun]/[UninstallDelete]
;      below), and wipes every directory this app or chimera-helper ever
;      wrote to, so nothing survives an uninstall: no orphaned process, no
;      leftover Program Files folder, no %ProgramData%\chimera (helper
;      token/logs), no %AppData%\com.chimera (chimera_settings.json --
;      which holds saved servers and any SSH passwords typed into the
;      "manage users"/deploy flow in plaintext, so leaving it behind on
;      uninstall would be a data-retention footgun, not just clutter).
;
; Build with: iscc scripts\windows-installer.iss (see -Iscc in
; build-app-windows.ps1, or run ISCC.exe directly after a build).

#define MyAppName "CHIMERA"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "CHIMERA"
#define MyAppExeName "chimera_tray.exe"
#define MyDistDir "..\chimera_tray"
#define MyIconFile "..\app\windows\runner\resources\app_icon.ico"

[Setup]
AppId={{9E6C6F1E-6C0B-4C2E-8B0C-5B7C4B7B8E71}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=chimera_setup
SetupIconFile={#MyIconFile}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Everything except the redistributable goes straight into {app}.
Source: "{#MyDistDir}\*"; DestDir: "{app}"; Excludes: "vc_redist.x64.exe"; Flags: recursesubdirs createallsubdirs ignoreversion
; The redistributable is only needed transiently during install.
Source: "{#MyDistDir}\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing Visual C++ Runtime..."; Flags: waituntilterminated skipifdoesntexist
Filename: "{app}\chimera-helper.exe"; Parameters: "install"; StatusMsg: "Installing CHIMERA network service..."; Flags: waituntilterminated runhidden skipifdoesntexist
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; 1. Best-effort restore of OS routes/DNS/firewall regardless of which mode
;    set them up (the ChimeraNetHelper service, or the direct CLI-elevation
;    fallback network_protection.dart uses when the helper isn't installed)
;    -- safe/idempotent to run even if nothing needs restoring (see
;    internal/winnet.RestorePowerShell). The installer already runs
;    elevated, so this needs no -setup-elevate/UAC prompt of its own. Must
;    run before the taskkill entries below: once chimera.exe is dead there's
;    nothing left to run its own cleanup.
Filename: "{app}\chimera.exe"; Parameters: "tun -setup-restore"; StatusMsg: "Restoring network settings..."; Flags: waituntilterminated runhidden skipifdoesntexist; RunOnceId: "RestoreNetworking"
; 2. Stop and remove the ChimeraNetHelper service (procRunner.Stop also runs
;    its own restore pass as part of stopping -- redundant with 1 above,
;    which is fine, RestorePowerShell tolerates being run twice).
Filename: "{app}\chimera-helper.exe"; Parameters: "uninstall"; StatusMsg: "Removing CHIMERA network service..."; Flags: waituntilterminated runhidden skipifdoesntexist; RunOnceId: "RemoveChimeraHelperService"
; 3. Kill any still-running chimera process. chimera_tray.exe (the tray GUI)
;    is a persistent background app with no "exit" the uninstaller can ask
;    for politely, and Windows refuses to delete a running .exe -- without
;    this, {app}'s files (including chimera_tray.exe itself) are silently
;    left behind and the process keeps running in Task Manager after
;    "uninstall" reports success, which is exactly the bug this fixes.
;    Safe to force-kill at this point: step 1/2 already restored networking,
;    so there's no route/firewall state left depending on a graceful exit.
Filename: "{sys}\taskkill.exe"; Parameters: "/IM chimera_tray.exe /F"; Flags: runhidden skipifdoesntexist; RunOnceId: "KillTray"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM chimera.exe /F"; Flags: runhidden skipifdoesntexist; RunOnceId: "KillCli"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM chimera-helper.exe /F"; Flags: runhidden skipifdoesntexist; RunOnceId: "KillHelper"

[UninstallDelete]
; {app} itself is covered by Inno automatically; these are the directories
; CHIMERA writes to outside {app} that Inno has no built-in knowledge of.
Type: filesandordirs; Name: "{commonappdata}\chimera"
Type: filesandordirs; Name: "{userappdata}\com.chimera"

[Code]
// Kill any already-running instance before installing/upgrading over it --
// otherwise the [Files] copy below can fail (or silently skip) on a locked
// chimera_tray.exe/chimera.dll the same way the uninstall bug did, if the
// user runs this installer again without closing the app first.
procedure KillRunningChimera();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM chimera_tray.exe /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM chimera.exe /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function InitializeSetup(): Boolean;
begin
  KillRunningChimera();
  Result := True;
end;
