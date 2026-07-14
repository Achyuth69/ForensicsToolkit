@echo off
REM ============================================================
REM  ForensicToolkit — Windows Deployment Script
REM  Copies Qt DLLs alongside the executable using windeployqt
REM ============================================================

setlocal

set BUILD_DIR=build_windows
set DEPLOY_DIR=deploy_windows
set EXE_PATH=%BUILD_DIR%\bin\Release\ForensicToolkit.exe

if not exist "%EXE_PATH%" (
    echo [ERROR] Executable not found: %EXE_PATH%
    echo         Run build_windows.bat first.
    exit /b 1
)

echo [1/3] Creating deployment directory...
if exist %DEPLOY_DIR% rmdir /s /q %DEPLOY_DIR%
mkdir %DEPLOY_DIR%

echo [2/3] Copying executable and resources...
copy "%EXE_PATH%" %DEPLOY_DIR%\
xcopy /s /i resources %DEPLOY_DIR%\resources

echo [3/3] Running windeployqt...
windeployqt --release --qmldir . %DEPLOY_DIR%\ForensicToolkit.exe

echo.
echo [SUCCESS] Deployment ready in: %DEPLOY_DIR%\
