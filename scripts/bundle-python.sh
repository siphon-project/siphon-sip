#!/usr/bin/env bash
# Stage the free-threaded CPython the release packages ship with the siphon
# binary.
#
#   scripts/bundle-python.sh <destination-dir>                    download, verify, stage
#   scripts/bundle-python.sh --print-rustflags <destination-dir>  RUSTFLAGS for the build
#
# The .deb / .rpm install <destination-dir> as /usr/lib/siphon/python and the
# tarball carries it as python/ next to the binary. The release build links
# against the staged copy:
#
#   PYO3_PYTHON=<destination-dir>/bin/python3.14t \
#   RUSTFLAGS="$(scripts/bundle-python.sh --print-rustflags <destination-dir>)" \
#       cargo build --release
#
# That gives the binary the rpath below, and CPython finds its standard library
# relative to the libpython it was loaded from, so nothing on the host has to
# provide a Python.
#
# Why bundle: siphon links libpython at build time. Debian, Ubuntu and RHEL do
# not ship a free-threaded libpython3.14t, so a package that depended on the
# system Python was GIL-limited, and failed to start wherever the system Python
# was not the exact minor version the binary had been linked against.
#
# The interpreter is a python-build-standalone build: relocatable, which a
# distro Python is not (its prefix is compiled in). It is pinned by version and
# SHA-256 here, so moving to a new CPython patch release is a reviewed change
# to this file. Bump PYTHON_VERSION / BUILD_DATE and both checksums together,
# taking the checksums from the release's own asset digests.
set -euo pipefail

PYTHON_VERSION="3.14.8"
BUILD_DATE="20261003"
SHA256_x86_64="076b84b988f4dee7ce3a8cb9b230fe5ef8f3c52df43e611edccc649a3433411d"
SHA256_aarch64="d828c22d4ec4929fe784789bb3a580704f31a8acc706151dcf7e40a01fc432b1"

# rpath for the release binary: the packaged location, then next to the binary
# for the tarball. The absolute entry comes first because the dynamic loader
# ignores $ORIGIN for a binary that carries file capabilities (setcap).
# shellcheck disable=SC2016
BUNDLE_RPATH='/usr/lib/siphon/python/lib:$ORIGIN/python/lib'

usage() {
    echo "usage: $0 <destination-dir>" >&2
    echo "       $0 --print-rustflags <destination-dir>" >&2
    exit 2
}

# The linker wants the unversioned libpython3.14t.so, which is a symlink in a
# normal install. It lives beside the bundle instead of in it, so the packaged
# tree stays free of symlinks.
link_directory() {
    printf '%s.link' "$(readlink -m "$1")"
}

if [ "${1:-}" = "--print-rustflags" ]; then
    [ "$#" -eq 2 ] || usage
    # -L: the interpreter's own sysconfig still names the directory it was
    # built in, so PyO3 cannot find libpython without being told.
    printf -- '-L native=%s -C link-arg=-Wl,-rpath,%s\n' "$(link_directory "$2")" "$BUNDLE_RPATH"
    exit 0
fi

[ "$#" -eq 1 ] || usage
destination="$1"

architecture="$(uname -m)"
case "$architecture" in
    x86_64)  expected_sha256="$SHA256_x86_64" ;;
    aarch64) expected_sha256="$SHA256_aarch64" ;;
    *) echo "error: no pinned interpreter for $architecture" >&2; exit 1 ;;
esac

minor="${PYTHON_VERSION%.*}"                      # 3.14
interpreter="python${minor}t"                     # python3.14t
library="libpython${minor}t.so.1.0"
stdlib="lib/python${minor}t"
archive="cpython-${PYTHON_VERSION}+${BUILD_DATE}-${architecture}-unknown-linux-gnu-freethreaded-install_only_stripped.tar.gz"
url="https://github.com/astral-sh/python-build-standalone/releases/download/${BUILD_DATE}/${archive//+/%2B}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --output "$work/$archive" "$url"
actual_sha256="$(sha256sum "$work/$archive" | cut -d' ' -f1)"
if [ "$actual_sha256" != "$expected_sha256" ]; then
    echo "error: checksum mismatch for $archive" >&2
    echo "  expected $expected_sha256" >&2
    echo "  actual   $actual_sha256" >&2
    exit 1
fi

# The archive unpacks to python/{bin,lib,include,share}.
tar -xzf "$work/$archive" -C "$work"
source_prefix="$work/python"

rm -rf "$destination"
mkdir -p "$destination/bin" "$destination/lib"

# The interpreter itself, so operators can install packages for their scripts:
#   /usr/lib/siphon/python/bin/python3.14t -m pip install <package>
cp "$source_prefix/bin/$interpreter" "$destination/bin/"
cp "$source_prefix/lib/$library" "$destination/lib/"
cp -r "$source_prefix/$stdlib" "$destination/lib/"
# The licences of CPython and of the libraries linked into it.
cp "$source_prefix/$stdlib/LICENSE.txt" "$destination/LICENSE.txt"

# Not needed to run scripts: the test suite, the GUI toolkits, the static
# library with its build config, and any bytecode cache.
for unused in test idlelib tkinter turtledemo "config-${minor}t-"*; do
    # shellcheck disable=SC2086  # $unused is a glob on purpose
    rm -rf "${destination:?}/$stdlib/"$unused
done
rm -f "$destination/$stdlib/lib-dynload/"_tkinter*.so
find "$destination" -type d -name __pycache__ -prune -exec rm -rf {} +

# This interpreter belongs to siphon, not to a distribution, so pip may
# install into it.
rm -f "$destination/$stdlib/EXTERNALLY-MANAGED"

# The packaging tools give every file matched by a glob one mode and do not
# all carry symlinks, so the tree must hold regular files only.
if [ -n "$(find "$destination" -type l -print -quit)" ]; then
    echo "error: the staged bundle contains symlinks:" >&2
    find "$destination" -type l >&2
    exit 1
fi

# Prove the staged copy is self-contained before anything links against it or
# packages it: run it from where it sits, with the unpacked source gone.
rm -rf "$source_prefix"
env -u PYTHONHOME -u PYTHONPATH "$destination/bin/$interpreter" -I -c "
import asyncio, json, sqlite3, ssl, sys, sysconfig
assert sysconfig.get_config_var('Py_GIL_DISABLED'), 'not a free-threaded build'
assert not sys._is_gil_enabled(), 'the GIL is enabled'
assert sys.version.split()[0] == sys.argv[1], (sys.version, sys.argv[1])
assert sys.base_prefix == sys.argv[2], (sys.base_prefix, sys.argv[2])
import pip
" "$PYTHON_VERSION" "$(readlink -f "$destination")"

link_directory="$(link_directory "$destination")"
rm -rf "$link_directory"
mkdir -p "$link_directory"
ln -s "$(readlink -f "$destination")/lib/$library" "$link_directory/${library%.1.0}"

echo "bundled free-threaded CPython $PYTHON_VERSION ($architecture) into $destination ($(du -sh "$destination" | cut -f1))"
