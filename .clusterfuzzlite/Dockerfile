FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:433319ea1a6bbea6c1db1915a5d385021908cc62026d9f0efda2270ef6060de3

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake nasm pkg-config zip \
    && rm -rf /var/lib/apt/lists/*

COPY . $SRC/rarpar
WORKDIR $SRC/rarpar
COPY .clusterfuzzlite/build.sh $SRC/
