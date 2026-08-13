# syntax=docker/dockerfile:1
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG TARGETARCH

COPY --chmod=0755 ${TARGETARCH}/rarpar /usr/local/bin/rarpar
COPY ${TARGETARCH}/share/ /usr/share/
COPY ${TARGETARCH}/README.md /usr/share/doc/rarpar/README.md
COPY ${TARGETARCH}/LICENSE /usr/share/licenses/rarpar/LICENSE
COPY ${TARGETARCH}/LICENSE.GPL-3.0-or-later /usr/share/licenses/rarpar/LICENSE.GPL-3.0-or-later
COPY ${TARGETARCH}/LICENSE.unrar-rs /usr/share/licenses/rarpar/LICENSE.unrar-rs

ENTRYPOINT ["/usr/local/bin/rarpar"]
