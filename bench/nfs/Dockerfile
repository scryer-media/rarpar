# The network-mount rig's images, built from bench/rarpar-bench (the compose
# build context). Every base is pinned by index digest.

FROM golang:1.26-trixie@sha256:aae9c439b447d24c93ee483408992857cf39a3fb6ab7fe53affc65d834891fa8 AS harness
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/rarpar-bench ./cmd/rarpar-bench

# Kernel nfsd needs only its userspace helpers here; the server itself is the
# VM kernel's, loaded with modprobe from the bind-mounted /lib/modules.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS server
RUN apt-get update \
 && apt-get install -y --no-install-recommends nfs-kernel-server rpcbind kmod procps netbase \
 && rm -rf /var/lib/apt/lists/*
COPY --from=harness /out/rarpar-bench /usr/local/bin/rarpar-bench
ENTRYPOINT ["rarpar-bench"]
CMD ["nfs", "server"]

# The client carries the pinned Rust toolchain so it can build the tree under
# test from the read-only source mount, and CMake for the reference.
FROM rust:1.97.1-slim-trixie@sha256:8e8cf8f7fd54a2d23d5a743b3a03f56e26b6c774276c33fa0595111704ebb15c AS client
RUN apt-get update \
 && apt-get install -y --no-install-recommends nfs-common netbase kmod cmake make g++ clang pkg-config perl patch strace iproute2 procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=harness /out/rarpar-bench /usr/local/bin/rarpar-bench
ENTRYPOINT ["rarpar-bench"]
CMD ["nfs", "client"]
