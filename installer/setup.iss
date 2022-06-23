; -- setup.iss --
; This script generates the adwatchd installer

#ifdef APP_VERSION
  #define AppVersion APP_VERSION
#else
  #define AppVersion "dev"
#endif


[Setup]
AppName=Ubuntu AD Watch Daemon
AppVersion={#AppVersion}
AppPublisher=Ubuntu
AppPublisherURL=https://www.ubuntu.com/
AppCopyright=Copyright (C) 2022 Canonical Ltd.
WizardStyle=modern
DefaultDirName={autopf}\Ubuntu\AD Watch Daemon
; Since no icons will be created in "{group}", we don't need the wizard
; to ask for a Start Menu folder name:
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\icon.ico
Compression=lzma2
SolidCompression=yes
WizardImageFile=assets\Ubuntu-Symbol.bmp
WizardSmallImageFile=assets\Ubuntu-Symbol-small.bmp
DisableWelcomePage=no
; SignTool=MsSign $f
OutputBaseFilename=adwatchd_setup

[Languages]
Name: en; MessagesFile: "compiler:Default.isl"
Name: fr; MessagesFile: "compiler:Languages\French.isl"

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nIt is recommended that you close all other applications before continuing.%n%nThe AD Watch Daemon is a service that will monitor a set of configured SYSVOL directories for changes and bump their respective GPT.ini versions, so that assets are not needlessly downloaded.%n%nAfter installation completes, you will be prompted to run the main executable program in order to configure and install the watcher service.

[Run]
Filename: {app}\adwatchd.exe; Description: Start interactive service installer; Flags: postinstall nowait skipifsilent unchecked

[UninstallRun]
Filename: {sys}\sc.exe; Parameters: "stop adwatchd"; Flags: runhidden; RunOnceId: "StopService"
Filename: {sys}\sc.exe; Parameters: "delete adwatchd"; Flags: runhidden; RunOnceId: "DelService"

[UninstallDelete]
Type: files; Name: "{app}\adwatchd.yaml"

[Files]
Source: "..\adwatchd.exe"; DestDir: "{app}"
Source: "..\README.md"; DestDir: "{app}"; Flags: isreadme
Source: "assets\adwatchd_shell.bat"; DestDir: "{app}"
Source: "assets\icon.ico"; DestDir: "{app}"

[Icons]
; Create a helper shortcut that starts an interactive command prompt with adwatchd.exe in the PATH
Name: "{autoprograms}\Start Command Prompt with adwatchd"; Filename: "{cmd}"; IconFilename: "{app}/icon.ico"; Parameters: "/E:ON /K ""{app}\adwatchd_shell.bat"""
