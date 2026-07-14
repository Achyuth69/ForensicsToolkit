# Building ForensicToolkit

## Quick Start — Windows (MSVC)

### 1. Install prerequisites
- [Qt 6.5+](https://www.qt.io/download) — select: MSVC 2019 64-bit, Qt Charts, Qt Network
- [CMake 3.21+](https://cmake.org/download/)
- [OpenSSL 3.x for Windows](https://slproweb.com/products/Win32OpenSSL.html) — Win64 OpenSSL
- Visual Studio 2019+ or Build Tools

### 2. Set environment (adjust paths)
```bat
set Qt6_DIR=C:\Qt\6.7.0\msvc2019_64\lib\cmake\Qt6
set OPENSSL_ROOT_DIR=C:\Program Files\OpenSSL-Win64
```

### 3. Build
```bat
scripts\build_windows.bat
```

Or manually:
```bat
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
```

### 4. Run
```bat
build\bin\Release\ForensicToolkit.exe
```

---

## Quick Start — Linux (GCC/Clang)

### 1. Install prerequisites (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install cmake ninja-build build-essential \
     libssl-dev \
     qt6-base-dev qt6-base-private-dev \
     libqt6charts6-dev libqt6sql6-sqlite \
     qt6-tools-dev
```

### 2. Build
```bash
chmod +x scripts/build_linux.sh
./scripts/build_linux.sh
```

Or manually:
```bash
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### 3. Run
```bash
./build/bin/ForensicToolkit
```

---

## Running Tests

```bash
cd build
ctest --output-on-failure -j4
```

Individual test:
```bash
./build/bin/test_hash
./build/bin/test_case_service
./build/bin/test_integrity
./build/bin/test_malware
./build/bin/test_filesystem
./build/bin/test_utils
./build/bin/test_integration_case
```

---

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `ON` | Build unit & integration tests |
| `BUILD_SAMPLE_PLUGIN` | `OFF` | Build the sample HashAnalyzerPlugin |
| `CMAKE_BUILD_TYPE` | `Release` | `Debug`, `Release`, `RelWithDebInfo` |

Example with options:
```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTS=ON \
  -DBUILD_SAMPLE_PLUGIN=ON
```

---

## Deployment (Windows)

After building, deploy Qt DLLs alongside the executable:

```bat
scripts\deploy_windows.bat
```

This calls `windeployqt` automatically and creates a `deploy_windows/` folder ready for distribution.

---

## IDE Setup

### VS Code
1. Install C/C++ and CMake Tools extensions
2. Open the project folder
3. CMake Tools will auto-detect CMakeLists.txt
4. Select your kit (MSVC / GCC)
5. Click Build

### CLion
1. File → Open → select project folder
2. CMake will auto-configure
3. Run → ForensicToolkit

### Qt Creator
1. File → Open File or Project → select CMakeLists.txt
2. Configure with your Qt6 kit
3. Build → Build All
