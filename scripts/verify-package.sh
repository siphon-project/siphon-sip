#!/usr/bin/env bash
# Install a built .deb / .rpm in a clean container and start siphon from it.
#
#   scripts/verify-package.sh <package.deb|package.rpm> <container-image>
#
# The image should be the oldest base the package claims to support and must
# not have a Python of its own, so a pass proves what the package promises: it
# installs with the dependencies it declares, the binary starts on that glibc,
# and it runs on the free-threaded interpreter it carries, with the GIL off.
# That last part reads the `python runtime` line siphon logs at startup.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <package.deb|package.rpm> <container-image>" >&2
    exit 2
fi
package="$(readlink -f "$1")"
image="$2"

case "$package" in
    *.deb) install='apt-get -qq update && apt-get -qq install -y --no-install-recommends /package/'"$(basename "$package")" ;;
    # rpm, not dnf: no repository is consulted, so everything the package
    # requires has to be in the base image already.
    *.rpm) install='rpm --install /package/'"$(basename "$package")" ;;
    *) echo "error: $package is neither a .deb nor an .rpm" >&2; exit 2 ;;
esac

docker run --rm --volume "$(dirname "$package"):/package:ro" "$image" bash -euo pipefail -c '
if command -v python3 >/dev/null; then
    echo "error: the image has its own python3, so this would not prove the bundle is used" >&2
    exit 1
fi

# The maintainer scripts reload systemd, which a container does not run.
printf "#!/bin/sh\nexit 0\n" > /usr/bin/systemctl
chmod +x /usr/bin/systemctl
export DEBIAN_FRONTEND=noninteractive

'"$install"'

cat > /tmp/siphon.yaml <<YAML
listen:
  udp: ["127.0.0.1:5060"]
domain:
  local: ["example.test"]
script:
  path: "/etc/siphon/scripts/proxy_default.py"
YAML

# siphon runs until stopped, so let it start and then end it.
timeout 5 /usr/bin/siphon --config /tmp/siphon.yaml > /tmp/siphon.log 2>&1 || status=$?
if [ "${status:-0}" -ne 124 ]; then
    echo "error: siphon exited on its own (status ${status:-0}) instead of running:" >&2
    cat /tmp/siphon.log >&2
    exit 1
fi

# Strip the colour codes the log is written with before matching.
sed -i "s/\x1b\[[0-9;]*m//g" /tmp/siphon.log
runtime="$(grep "python runtime" /tmp/siphon.log || true)"
echo "$runtime"
for expected in "free_threaded=true" "gil_enabled=false" "prefix=/usr/lib/siphon/python"; do
    if ! printf "%s" "$runtime" | grep -q -- "$expected"; then
        echo "error: the python runtime line lacks $expected:" >&2
        cat /tmp/siphon.log >&2
        exit 1
    fi
done
grep -q "SIPhon ready" /tmp/siphon.log

# Operators install packages for their scripts with the bundled pip.
/usr/lib/siphon/python/bin/python3.14t -m pip --version
'

echo "verified $(basename "$package") on $image"
