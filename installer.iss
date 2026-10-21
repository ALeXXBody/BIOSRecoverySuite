; Inno Setup script for BIOS Recovery Suite
; Compiled on CI with ISCC.exe after the PyInstaller build.

#define MyAppName "BIOS Recovery Suite"
#define MyAppVersion "0.4.2"
#define MyAppPublisher "ALeXXBody"
#define MyAppExeName "BIOSRecoverySuite.exe"

[Setup]
AppId={{7C1E4B9A-52D4-4E3E-9B0F-2A8C6D5E1F30}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\BIOSRecoverySuite
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=BIOSRecoverySuite-Setup-{#MyAppVersion}
SetupIconFile=assets\icon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Wipe the previous install before unpacking. Qt resolves DLLs from the app
; folder FIRST, so a single stale DLL left behind by an older build (a
; hand-injected ICU, an old Qt, a leftover runtime) shadows the correct
; system one and QtWidgets fails with "The specified procedure could not be
; found" even though the new build is perfectly good. The app stores no user
; data here, so a clean wipe on every install is safe.
Type: filesandordirs; Name: "{app}\*"

[Files]
Source: "dist\BIOSRecoverySuite\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent
