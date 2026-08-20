@echo off
REM Windows cmd wrapper — no PowerShell execution policy required.
setlocal
cd /d "%~dp0.."
if /I "%~1"=="--uninstall" goto uninstall
if /I "%~1"=="-u" goto uninstall
git config core.hooksPath .githooks
if errorlevel 1 (
  echo error: git config failed. Is Git for Windows installed and on PATH?
  exit /b 1
)
echo Installed Git hooks (local core.hooksPath=.githooks).
git config --get core.hooksPath
echo Requires Git for Windows so hooks run under bash.
exit /b 0

:uninstall
git config --unset core.hooksPath
echo Removed local core.hooksPath.
exit /b 0
