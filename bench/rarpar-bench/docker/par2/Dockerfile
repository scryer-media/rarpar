FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS build

# The source tarball is staged into the build context by the harness, which
# resolved it mirror-first, verified its signed provenance, and checked it
# against the reviewed SHA-256. The build downloads no source.
COPY par2.tar.gz /tmp/par2.tar.gz

RUN set -eux; \
    apt-get update; \
    apt-get install --yes --no-install-recommends autoconf automake build-essential; \
    mkdir -p /src; \
    tar -xzf /tmp/par2.tar.gz -C /src --strip-components=1; \
    cd /src; ./automake.sh; ./configure --prefix=/opt/par2; make -j"$(nproc)"; make install

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN set -eux; apt-get update; apt-get install --yes --no-install-recommends libgomp1 libstdc++6; rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/par2/bin/par2 /usr/local/bin/par2
ENTRYPOINT ["par2"]
