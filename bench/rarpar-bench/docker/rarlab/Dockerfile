FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG RAR_BINARY=rar

# The archive is staged into the build context by the harness, which resolved it
# mirror-first, verified its signed provenance, and checked it against the
# reviewed SHA-256. The build downloads nothing.
COPY rar.tar.gz /tmp/rar.tar.gz

RUN set -eux; \
    apt-get update; \
    apt-get install --yes --no-install-recommends tar; \
    case "$RAR_BINARY" in ''|.|..|*/*|*\\*) exit 64;; esac; \
    mkdir -p /opt/rar; \
    tar -xzf /tmp/rar.tar.gz -C /opt/rar; \
    install -m 0755 "/opt/rar/rar/$RAR_BINARY" /usr/local/bin/rar; \
    rm -rf /tmp/rar.tar.gz /opt/rar /var/lib/apt/lists/*

ENTRYPOINT ["rar"]
