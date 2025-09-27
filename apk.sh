#!/bin/bash

# APK Decompiler Script
# Usage: ./apk.sh <package_name> 

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions (stderr only)
print_status()   { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
print_success()  { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }
print_warning()  { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }
print_error()    { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Check if package name is provided
if [ $# -eq 0 ]; then
    print_error "No package name provided"
    echo "Usage: $0 <package_name> [user_id]" >&2
    exit 1
fi

PACKAGE_NAME="$1"
USER_ID="${2:-}"

# Dependency check
check_dependencies() {
    local missing=()
    for cmd in adb apktool; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

# Device check
check_device() {
    print_status "Checking for connected devices..."
    if ! adb devices | grep -q "device$"; then
        print_error "No authorized device found"
        adb devices >&2
        exit 1
    fi
    print_success "Device connected and authorized"
}

# Get all users
find_users() {
    adb shell pm list users 2>/dev/null | grep "UserInfo" | sed 's/.*{\([0-9]*\).*/\1/'
}

# Find package path(s)
find_package_path() {
    print_status "Finding package path(s) for: $PACKAGE_NAME"

    local paths=""

    if [ -n "$USER_ID" ]; then
        paths=$(adb shell pm path --user "$USER_ID" "$PACKAGE_NAME" 2>/dev/null | sed 's/^package://')
    fi

    if [ -z "$paths" ]; then
        for user in $(find_users); do
            paths=$(adb shell pm path --user "$user" "$PACKAGE_NAME" 2>/dev/null | sed 's/^package://')
            [ -n "$paths" ] && break
        done
    fi

    if [ -z "$paths" ]; then
        paths=$(adb shell pm path "$PACKAGE_NAME" 2>/dev/null | sed 's/^package://')
    fi

    if [ -z "$paths" ]; then
        print_error "Package not found: $PACKAGE_NAME"
        exit 1
    fi

    echo "$paths"  # stdout only, clean
}

# Pull APK(s)
pull_apk() {
    local paths="$1"
    local i=1

    for path in $paths; do
        local out="apk_part_${i}.apk"
        print_status "Pulling $path → $out"
        adb pull "$path" "$out" >&2
        print_success "Saved: $out"
        i=$((i+1))
    done
}

# Decompile base.apk (first file)
decompile_apk() {
    local apk_file="apk_part_1.apk"
    local out_dir="decompiled"

    [ ! -f "$apk_file" ] && { print_error "$apk_file not found"; exit 1; }

    rm -rf "$out_dir"
    print_status "Decompiling $apk_file..."
    if apktool d "$apk_file" -o "$out_dir"; then
        print_success "Decompiled to: $out_dir"
    else
        print_error "apktool failed"
        exit 1
    fi
}

# Main
main() {
    echo "================================================" >&2
    echo "           APK Decompiler Script" >&2
    echo "================================================" >&2

    check_dependencies
    check_device

    local paths
    paths=$(find_package_path)
    pull_apk "$paths"
    decompile_apk

    print_success "Process completed"
}

main

