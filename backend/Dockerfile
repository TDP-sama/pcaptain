# fastscan is built with the compiler of the Debian release it runs on
# (bookworm, like python:3.10-slim-bookworm below), so the C++ runtime and
# libpcap it links against are the ones installed at runtime. The gcc:13 image
# used before links a newer libstdc++ than bookworm ships, and fastscan only
# worked while the runtime image happened to be a newer Debian.
FROM debian:bookworm-slim AS fastscan-builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        g++ \
        make \
        cmake \
        libpcap-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Copy entire fast_scan project
COPY fast_scan/ .

# Build with CMake
RUN rm -rf build && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make

FROM python:3.10-slim-bookworm

# tshark asks whether non-root users may capture; we only read files, so the
# noninteractive default (no) is fine. libpcap0.8 is what fastscan links to
# (named explicitly instead of relying on tshark pulling it in).
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled fastscan binary from build directory
COPY --from=fastscan-builder /build/build/fastscan /usr/local/bin/fastscan
# Fail the build, not the first scan, if a library fastscan needs is missing.
RUN ! (ldd /usr/local/bin/fastscan 2>&1 | grep "not found")

WORKDIR /app

COPY backend/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY backend .
# Copy entrypoint script
COPY backend/config/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
