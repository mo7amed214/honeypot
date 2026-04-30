FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libopen62541-1-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY opcua_server/server.c .
RUN gcc -O2 -Wall -std=c11 server.c -o server \
    $(pkg-config --cflags --libs open62541)

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libopen62541-1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/server /usr/local/bin/opcua-server
EXPOSE 4840
CMD ["/usr/local/bin/opcua-server"]
