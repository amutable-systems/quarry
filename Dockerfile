# SPDX-License-Identifier: Apache-2.0
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

# Build using an older Debian so that the binaries are built against an older
# glibc which will work with our GHA CI environment.
ARG SD_DEBIAN_RELEASE=bookworm
ARG SD_DEBIAN_IMAGE_DIGEST=sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931

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
# TODO: Create a renovate job that maintains this.
ARG LIBPATHRS_VERSION=0.2.5
ARG LIBPATHRS_SHA256=f8f4a9419eb839cd5decbd120b65f0495bf6eac07155477fe39a8c2a23da589d
ADD --checksum=sha256:${LIBPATHRS_SHA256} \
    https://github.com/cyphar/libpathrs/releases/download/v${LIBPATHRS_VERSION}/libpathrs-${LIBPATHRS_VERSION}.tar.xz \
    /usr/src/libpathrs.tar.xz
# TODO: Switch to ADD --unpack rather than a separate extraction stage, once
# Podman supports it. <https://github.com/podman-container-tools/buildah/issues/6655>
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
# systemd-build: builds systemd daemons from upstream git for conformance
# tests against real varlink services
# --------------------------------------------------------------------------- #
FROM debian:${SD_DEBIAN_RELEASE}@${SD_DEBIAN_IMAGE_DIGEST} AS systemd-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        git \
        gperf \
        libcap-dev \
        libmount-dev \
        meson \
        ninja-build \
        pkgconf \
        python3-jinja2 \
        rename && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*

# TODO: Create a renovate job that maintains this.
ARG SYSTEMD_COMMIT=15458a89f1e39223c958f9ba06f4355b7d60a3ed
RUN git init -q /usr/src/systemd && \
    git -C /usr/src/systemd fetch --depth=1 \
        https://github.com/systemd/systemd.git "${SYSTEMD_COMMIT}" && \
    git -C /usr/src/systemd checkout -q FETCH_HEAD

# Build systemd with as few features as possible to reduce the number of
# dependencies and build times, especially as we currently only test against
# systemd-hostnamed which has very few features.
RUN meson setup /usr/src/systemd/build /usr/src/systemd \
        --auto-features=disabled \
        --buildtype=release \
        -Dmode=release
ARG SD_BINARIES=systemd-hostnamed
# Build the .standalone variants of the binaries, which will statically link
# against libsystemd-shared, making the binaries entirely self-contained.
RUN printf '%s.standalone\0' $SD_BINARIES | \
        xargs -0 ninja -C /usr/src/systemd/build --
RUN cd /usr/src/systemd/build && \
    rename 's/\.standalone$//' * && \
    install -Dt /opt/systemd $SD_BINARIES

# --------------------------------------------------------------------------- #
# systemd-export: provides just the systemd binaries for -o type=local builds
# --------------------------------------------------------------------------- #
FROM scratch AS systemd-export
COPY --from=systemd-build /opt/systemd/ /

# --------------------------------------------------------------------------- #
# export: provides just the quarry binaries for -o type=local builds
# --------------------------------------------------------------------------- #
FROM scratch AS export
COPY --from=quarry-build /opt/quarry/bin/ /
