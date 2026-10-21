; Bộ cài D365 Security Role Analyzer — build bằng installer\build-installer.ps1.
; Phiên bản, thư mục publish và edition (Full / Viewer) được truyền vào qua /D khi gọi ISCC.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\publish"
#endif
#ifndef Edition
  #define Edition "Full"
#endif

; Hai edition có AppId và thư mục cài riêng nên cài song song trên cùng máy được.
#if Edition == "Viewer"
  #define AppName "D365 Security Role Analyzer Viewer"
  #define AppIdValue "{{B2E84A61-7C3F-4D19-8A56-0E9F3C1D7B24}"
  #define SetupName "SecurityRoleAnalyzer-Viewer-Setup-"
#else
  #define AppName "D365 Security Role Analyzer"
  #define AppIdValue "{{6F1C2B7E-3D4A-4E59-9B21-5A7C0D8E4F13}"
  #define SetupName "SecurityRoleAnalyzer-Setup-"
#endif
#define AppExe "SecurityRoleAnalyzer.exe"

[Setup]
AppId={#AppIdValue}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=duytoerp
AppPublisherURL=https://github.com/duytoerp/d365_security_role_analyzer
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Mặc định cài cho riêng user hiện tại (không cần quyền admin); user có thể chọn cài cho mọi người.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename={#SetupName}{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autoprograms}\{#AppName} (Demo)"; Filename: "{app}\{#AppExe}"; Parameters: "--demo"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
; Ứng dụng tự cập nhật chạy bộ cài với /SILENT /relaunch=1: cài xong thì mở lại app.
; Cài im lặng bình thường (IT triển khai hàng loạt) không truyền tham số này nên không mở app.
Filename: "{app}\{#AppExe}"; Flags: nowait runasoriginaluser; Check: RelaunchRequested

[Code]
function RelaunchRequested: Boolean;
begin
  Result := ExpandConstant('{param:relaunch|0}') = '1';
end;
