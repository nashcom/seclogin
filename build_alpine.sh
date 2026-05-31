#!/bin/bash
# Build a statically linked seclogin binary inside an Alpine container
# Usage: ./build_alpine.sh [commands...] [--quick]
#
# Commands (can be combined):
#   (no arg)  — compile only
#   rebuild   — remove build image and rebuild it, then compile
#   install   — compile + install to host (requires root)
#   test      — run test suite (no recompile unless combined with rebuild/all)
#   all       — compile + run test suite
#
# Options:
#   --quick   — skip delay-heavy tests (~5s instead of ~27s)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

IMAGE="seclogin-build"

error()
{
    echo "ERROR: $*" >&2
    exit 1
}

header()
{
    echo
    echo "------------------------------------------------------------"
    echo " $*"
    echo "------------------------------------------------------------"
    echo
}

# ---------------------------------------------------------------------------
# Parse arguments — one loop, derive action flags
# ---------------------------------------------------------------------------

fRebuild=0
fCompile=1
fTest=0
fInstall=0
fQuick=0

for arg in "$@"; do
    case "$arg" in
        rebuild) fRebuild=1 ;;
        install) fInstall=1 ;;
        test)    fCompile=0; fTest=1 ;;
        all)     fTest=1 ;;
        --quick) fQuick=1 ;;
        *)
            error "Unknown option: '$arg' — valid: rebuild | install | test | all | --quick"
            ;;
    esac
done

# rebuild implies compile
[ "$fRebuild" -eq 1 ] && fCompile=1

command -v docker > /dev/null 2>&1 || error "docker not found"

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

# 1. Rebuild image
if [ "$fRebuild" -eq 1 ]; then
    header "Rebuilding $IMAGE"
    docker rmi "$IMAGE" 2>/dev/null || true
    docker build -f "$SCRIPT_DIR/Dockerfile.build" -t "$IMAGE" "$SCRIPT_DIR"
fi

# 2. Ensure image exists
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
    header "Build image not found — creating $IMAGE"
    docker build -f "$SCRIPT_DIR/Dockerfile.build" -t "$IMAGE" "$SCRIPT_DIR"
else
    [ "$fRebuild" -eq 0 ] && echo "Using existing build image: $IMAGE"
fi

# 3. Compile
if [ "$fCompile" -eq 1 ]; then
    header "Building static seclogin in Alpine container"

    docker run --rm \
        -v "$SCRIPT_DIR":/build \
        -w /build \
        "$IMAGE" \
        sh -c "make -f Makefile.alpine clean all"

    if [ ! -f "$SCRIPT_DIR/$BIN" ]; then
        error "Build failed — binary not found"
    fi

    header "Binary info"
    file "$SCRIPT_DIR/$BIN"
    ls -lh "$SCRIPT_DIR/$BIN"
else
    if [ ! -f "$SCRIPT_DIR/$BIN" ]; then
        error "Binary not found — run $0 first to compile"
    fi
    echo "Using existing binary: $(ls -lh $SCRIPT_DIR/$BIN)"
fi

# 4. Run tests
if [ "$fTest" -eq 1 ]; then
    header "Running test suite in container"

    QUICK_FLAG=""
    [ "$fQuick" -eq 1 ] && QUICK_FLAG="--quick"

    docker run --rm \
        --cap-add SETUID \
        --cap-add SETGID \
        -v "$SCRIPT_DIR":/build \
        -w /build \
        "$IMAGE" \
        bash -c "ROOT_DIR=/build bash <(dos2unix < /build/testing/test_seclogin.sh) $QUICK_FLAG"
fi

# 5. Install on host
if [ "$fInstall" -eq 1 ]; then
    if [ "$(id -u)" -ne 0 ]; then
        error "Install requires root (sudo $0 install)"
    fi

    header "Installing $BIN on host: $INSTALL_DIR"

    cp "$SCRIPT_DIR/$BIN" "$INSTALL_DIR/$BIN"
    chown "root:$ADMIN_GROUP" "$INSTALL_DIR/$BIN"
    chmod "$MODE" "$INSTALL_DIR/$BIN"

    ls -lh "$INSTALL_DIR/$BIN"

    header "Installing $BIN_GATE on host: $INSTALL_DIR"

    if ! getent passwd "$AUTH_USER" > /dev/null 2>&1; then
        echo "WARNING: User '$AUTH_USER' not found — $BIN_GATE will be owned by root:root"
        echo "         Run sudo ./create_seclogin_user.sh then re-run sudo $0 install"
        cp "$SCRIPT_DIR/$BIN" "$INSTALL_DIR/$BIN_GATE"
        chown "root:root" "$INSTALL_DIR/$BIN_GATE"
        chmod "$MODE_GATE" "$INSTALL_DIR/$BIN_GATE"
    else
        cp "$SCRIPT_DIR/$BIN" "$INSTALL_DIR/$BIN_GATE"
        chown "$AUTH_USER:$AUTH_USER" "$INSTALL_DIR/$BIN_GATE"
        chmod "$MODE_GATE" "$INSTALL_DIR/$BIN_GATE"
    fi

    ls -lh "$INSTALL_DIR/$BIN_GATE"
    echo "Done."
fi

# 6. Summary if nothing ran
if [ "$fTest" -eq 0 ] && [ "$fInstall" -eq 0 ]; then
    echo
    echo "Done. To install on host:    sudo $0 install"
    echo "      To run tests:          $0 test [--quick]"
    echo "      To rebuild image:      $0 rebuild"
    echo
fi
