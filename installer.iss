; Inno Setup script for BIOS Recovery Suite
; Compiled on CI with ISCC.exe after the PyInstaller build.

#define MyAppName "BIOS Recovery Suite"
; The version is not written here. CI passes bios_recovery.__version__ on the command line:
;   ISCC /DMyAppVersion=<version> installer.iss
#ifndef MyAppVersion
#error "Pass the version on the command line: ISCC /DMyAppVersion=<version> installer.iss"
#endif
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
; Remove the previous build before unpacking. Qt resolves DLLs from the app
; folder FIRST, so a stale DLL left behind by an older build shadows the correct
; one. Only this application's own files are removed, never the whole folder:
; the folder itself is checked in [Code] before installation starts.
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\{#MyAppExeName}"

[Files]
Source: "dist\BIOSRecoverySuite\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Code]
function IsDriveRoot(Dir: string): Boolean;
begin
  Result := Length(RemoveBackslash(Dir)) <= 2;
end;

function FolderHasForeignFiles(Dir: string): Boolean;
var
  FindRec: TFindRec;
  Found: Boolean;
begin
  Result := False;
  if not DirExists(Dir) then
    Exit;
  { A folder this application installed before has its uninstaller or its runtime folder. }
  if FileExists(AddBackslash(Dir) + 'unins000.exe') then
    Exit;
  if DirExists(AddBackslash(Dir) + '_internal') then
    Exit;
  Found := FindFirst(AddBackslash(Dir) + '*', FindRec);
  while Found do
  begin
    if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
    begin
      Result := True;
      Found := False;
    end
    else
      Found := FindNext(FindRec);
  end;
  FindClose(FindRec);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpSelectDir then
  begin
    if IsDriveRoot(WizardDirValue) then
    begin
      MsgBox('Choose a folder for the application, not the root of a drive.', mbError, MB_OK);
      Result := False;
    end
    else if FolderHasForeignFiles(WizardDirValue) then
    begin
      MsgBox('That folder already contains files that BIOS Recovery Suite did not install. Choose a different folder.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;
