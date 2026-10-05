# syntax=docker/dockerfile:1.7

# siphon as the system under test of an independent SIP call test suite.
#
# The suite drives calls through siphon from one user agent to another, with
# media anchored on rtpproxy, and checks three things siphon's own SIPp
# scenarios cannot: that a second SIP stack is satisfied by every exchange,
# that every SDP it sees points at the relay, and that the relay's own session
# and command counters come out exactly as expected (a leaked or doubled media
# session shows up there and nowhere else).
#
# Shape, the same one the suite's other systems under test use in their own
# repositories: start from the published rtpproxy image, add the system under
# test, copy in the suite and rtpproxy's control tools, run the suite as the
# entrypoint. siphon is not compiled here: it comes from the image CI already
# builds once per run, so this tests the free-threaded build that ships.
#
# Build context: this directory, with the suite checked out in dist/voiptests
# and rtpproxy in dist/rtpproxy.

ARG SIPHON_IMAGE=sipp-siphon:latest
ARG BASE_IMAGE=ghcr.io/sippy/rtpproxy:latest

FROM ${SIPHON_IMAGE} AS siphon

FROM ${BASE_IMAGE}

USER root
ENV DEBIAN_FRONTEND=noninteractive

# What the suite itself needs: its preprocessor and a Python for its two user
# agents. This is the distribution's interpreter, separate from the one siphon
# embeds.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        gpp \
        python3 \
        python3-pip \
        python-is-python3 \
    && rm -rf /var/lib/apt/lists/*

# siphon and the interpreter it embeds, as the siphon image lays them out.
COPY --from=siphon /opt/python /opt/python
COPY --from=siphon /usr/local/bin/siphon /opt/siphon/libexec/siphon
RUN PY_BIN=$(find /opt/python -type f -name python3.14t -perm -u+x | head -n1) && \
    PY_PREFIX=$(dirname $(dirname "$PY_BIN")) && \
    echo "$PY_PREFIX/lib" > /etc/ld.so.conf.d/python3.14t.conf && \
    ldconfig && \
    mkdir -p /opt/siphon/target/release && \
    printf '#!/bin/sh\n# The embedded interpreter is the free-threaded one from the siphon image, not\n# the distribution python3 that is first on PATH for the suite.\nexport PYTHONHOME="%s"\nexport PYTHON_GIL=0\nexport PYTHONFAULTHANDLER=1\nexec /opt/siphon/libexec/siphon "$@"\n' "$PY_PREFIX" \
        > /opt/siphon/target/release/siphon && \
    chmod 755 /opt/siphon/target/release/siphon

COPY dist/rtpproxy /opt/rtpproxy
COPY dist/voiptests /opt/voiptests

RUN python -m pip install --break-system-packages -r /opt/voiptests/requirements.txt

# The suite looks for the binary at ${MM_ROOT}/target/release/siphon.
ENV MM_TYPE=siphon \
    MM_BRANCH=main \
    MM_ROOT=/opt/siphon \
    RTPP_BRANCH=DOCKER \
    RTPPC_TYPE=udp \
    RTPPROXY_DIST=/opt/rtpproxy

WORKDIR /opt/voiptests
ENTRYPOINT ["sh", "-x", "./test_run.sh"]
