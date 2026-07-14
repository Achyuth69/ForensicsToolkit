#!/usr/bin/env bash
# ============================================================
#  ForensicToolkit — Linux Build Script
#  Requirements: Qt6, CMake 3.21+, OpenSSL, GCC 11+ or Clang 14+
# ============================================================

set -euo pipefail

BUILD_DIR="build_linux"
BUILD_TYPE="${1:-Release}"

echo ""
echo "[ForensicToolkit] Linux Build Script"
echo "======================================="

# ── Dependency check ──────────────────────────────────────────
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "[ERROR] $1 not found. $2"
        exit 1
    fi
}

check_dep cmake  "Install: sudo apt install cmake"
check_dep ninja  "Install: sudo apt install ninja-build  (or use -G 'Unix Makefiles')"
check_dep g++    "Install: sudo apt install g++"

echo "[INFO]  CMake version: $(cmake --version | head -1)"
echo "[INFO]  Compiler:      $(g++ --version | head -1)"

# ── Configure ─────────────────────────────────────────────────
echo ""
echo "[1/4] Configuring (${BUILD_TYPE})..."
cmake -S . -B "${BUILD_DIR}" \
    -GNinja \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_TESTS=ON \
    "$@"

# ── Build ─────────────────────────────────────────────────────
echo ""
echo "[2/4] Building..."
cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

# ── Tests ─────────────────────────────────────────────────────
echo ""
echo "[3/4] Running tests..."
cd "${BUILD_DIR}"
ctest --output-on-failure
cd ..

echo ""
echo "[4/4] Done!"
echo "  Executable: ${BUILD_DIR}/bin/ForensicToolkit"
echo ""
