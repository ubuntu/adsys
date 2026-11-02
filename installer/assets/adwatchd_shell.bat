@ECHO OFF

REM This is the current directory which contains adwatchd
SET ADWATCHD_DIR=%~dp0

REM Add the adwatchd bindir to the PATH
SET PATH=%ADWATCHD_DIR%;%PATH%

REM Display adwatchd version
adwatchd.exe --help
