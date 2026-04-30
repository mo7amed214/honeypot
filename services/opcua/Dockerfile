FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake curl ca-certificates python3 pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Download and compile open62541 statically (no distro package available)
ARG OPEN62541_VER=1.3.12
RUN curl -fsSL \
    "https://github.com/open62541/open62541/archive/v${OPEN62541_VER}.tar.gz" \
    | tar -xzf - -C /tmp
RUN cmake -B /tmp/oa-build \
      -S "/tmp/open62541-${OPEN62541_VER}" \
      -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DBUILD_SHARED_LIBS=OFF \
    && cmake --build /tmp/oa-build -j"$(nproc)" \
    && cmake --install /tmp/oa-build --prefix /usr/local

WORKDIR /build
COPY opcua_server/server.c .
RUN gcc -O2 -Wall -std=c11 server.c -o server \
    $(pkg-config --cflags --libs open62541) -lpthread -lm

# Runtime — binary is statically linked against open62541, no extra libs needed
FROM ubuntu:22.04
COPY --from=builder /build/server /usr/local/bin/opcua-server
EXPOSE 4840
CMD ["/usr/local/bin/opcua-server"]
