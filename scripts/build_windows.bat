@echo off
REM ============================================================
REM  ForensicToolkit — Windows Build Script
REM  Requirements: Qt6, CMake 3.21+, OpenSSL, MSVC or MinGW
REM ============================================================

setlocal

set BUILD_DIR=build_windows
set BUILD_TYPE=Release

echo.
echo [ForensicToolkit] Windows Build Script
echo ========================================

REM Check cmake
where cmake >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cmake not found. Install CMake 3.21+ and add to PATH.
    exit /b 1
)

REM Check Qt6 path - adjust if needed
if not defined Qt6_DIR (
    echo [WARN] Qt6_DIR not set. CMake will attempt auto-detection.
    echo        Set Qt6_DIR to your Qt6 CMake config dir if the build fails.
    echo        Example: set Qt6_DIR=C:\Qt\6.7.0\msvc2019_64\lib\cmake\Qt6
)

echo.
echo [1/4] Creating build directory: %BUILD_DIR%
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo.
echo [2/4] Configuring CMake (%BUILD_TYPE%)...
cmake -S . -B %BUILD_DIR% ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DBUILD_TESTS=ON ^
    %*

if errorlevel 1 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

echo.
echo [3/4] Building...
cmake --build %BUILD_DIR% --config %BUILD_TYPE% --parallel

if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo [4/4] Running tests...
cd %BUILD_DIR%
ctest --output-on-failure -C %BUILD_TYPE%
cd ..

echo.
echo [SUCCESS] Build complete!
echo   Executable: %BUILD_DIR%\bin\%BUILD_TYPE%\ForensicToolkit.exe
echo.
