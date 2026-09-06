FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS build

# The source archive is the pinned par3cmdline commit's GitHub tarball, staged
# into the build context by the harness, which resolved it mirror-first,
# verified its signed provenance, and checked it against the reviewed BLAKE3
# digest. The build downloads no source. The tree vendors its own BLAKE3 and
# Leopard sources, so nothing else is fetched either.
COPY par3.tar.gz /tmp/par3.tar.gz

RUN set -eux; \
    apt-get update; \
    apt-get install --yes --no-install-recommends cmake g++ gcc make; \
    mkdir -p /src; \
    tar -xzf /tmp/par3.tar.gz -C /src --strip-components=1; \
    cd /src; \
    cmake -D CMAKE_BUILD_TYPE=Release -S src -B build; \
    cmake --build build -j"$(nproc)"; \
    install -m 0755 build/par3cmd/par3 /usr/local/bin/par3

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN set -eux; apt-get update; apt-get install --yes --no-install-recommends libstdc++6; rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/par3 /usr/local/bin/par3
ENTRYPOINT ["par3"]
