# Copyright (C) 2026 Amutable GmbH

# Builds the quarry binaries in a container with libpathrs.a so you don't need
# to deal with managing a host install of libpathrs. To build, just do:
#
#   just build-all-in-container
#
# or do it manually with
#
#   docker buildx build --target export -o type=local,dest=. .

ARG DEBIAN_RELEASE=trixie
ARG RUST_VERSION=1.96
ARG GO_VERSION=1.26

ARG RUST_IMAGE_DIGEST=sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376
ARG GO_IMAGE_DIGEST=sha256:68b7145ec43d1820b9a56704554b53d1520aa2a15cb5233e374188a31b2a1bce

# --------------------------------------------------------------------------- #
# libpathrs-build: builds libpathrs.a from source
# --------------------------------------------------------------------------- #
FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE}@${RUST_IMAGE_DIGEST} AS libpathrs-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        clang \
        lld \
        make \
        pkg-config && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*

# Should be kept in sync with go.mod.
ARG LIBPATHRS_VERSION=0.2.5
ARG LIBPATHRS_SHA256=f8f4a9419eb839cd5decbd120b65f0495bf6eac07155477fe39a8c2a23da589d
ADD --checksum=sha256:${LIBPATHRS_SHA256} \
    https://github.com/cyphar/libpathrs/releases/download/v${LIBPATHRS_VERSION}/libpathrs-${LIBPATHRS_VERSION}.tar.xz \
    /usr/src/libpathrs.tar.xz
RUN tar -xJf /usr/src/libpathrs.tar.xz -C /usr/src

# Build and install libpathrs (with no libpathrs.so).
WORKDIR /usr/src/libpathrs-${LIBPATHRS_VERSION}
RUN make release && \
    DESTDIR=/opt/libpathrs ./install.sh \
        --disable-dynamic \
        --prefix=/usr \
        --libdir=/usr/lib

# --------------------------------------------------------------------------- #
# quarry-build: builds quarry binaries with static libpathrs
# --------------------------------------------------------------------------- #
FROM golang:${GO_VERSION}-${DEBIAN_RELEASE}@${GO_IMAGE_DIGEST} AS quarry-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        just \
        pkg-config && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*

# Pre-pull Go dependencies to reduce cache-bust costs.
WORKDIR /usr/src/quarry
COPY go.mod go.sum .
RUN go mod download

# Install libpathrs.
COPY --from=libpathrs-build /opt/libpathrs/ /

# Should be kept in sync with justfile.
ARG BUILDTAGS="http insecure"

COPY . /usr/src/quarry
ENV OUTDIR=/opt/quarry/bin
RUN just build-all

# --------------------------------------------------------------------------- #
# export: provides just the quarry binaries for -o type=local builds
# --------------------------------------------------------------------------- #
FROM scratch AS export
COPY --from=quarry-build /opt/quarry/bin/ /
