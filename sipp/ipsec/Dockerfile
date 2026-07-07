# Build SIPp with IPSec support from the carstenbock/sipp_ipsec fork
# This fork adds -ipsec flag, ipsec_setup/ipsec_teardown actions,
# AKA authentication, and xfrm SA/SP management for VoLTE testing.

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        g++ \
        make \
        cmake \
        pkg-config \
        libssl-dev \
        libsctp-dev \
        libpcap-dev \
        libncurses-dev \
        libmnl-dev \
        libgtest-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --recurse-submodules is required: SIPp vendors pugixml (and gtest) as git
# submodules, so without it third_party/pugixml is empty and CMake fails with
# "Cannot find source file: .../pugixml/src/pugixml.cpp".
RUN git clone --depth 1 --recurse-submodules --shallow-submodules \
        https://github.com/carstenbock/sipp_ipsec.git /build/sipp

WORKDIR /build/sipp

RUN cmake . \
        -DUSE_SSL=ON \
        -DUSE_SCTP=ON \
        -DUSE_PCAP=ON \
        -DUSE_GSL=OFF \
        -DUSE_IPSEC=ON \
    && make -j$(nproc)

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libsctp1 \
        libpcap0.8 \
        libncurses6 \
        libncursesw6 \
        libmnl0 \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/sipp/sipp /usr/local/bin/sipp

ENTRYPOINT ["sipp"]
