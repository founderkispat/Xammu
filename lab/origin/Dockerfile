# XAMMU laboratory origin.
#
# Multi-stage so that a third party needs only Docker to rebuild it: the Go
# toolchain is pinned by immutable digest, the runtime base is pinned by
# immutable digest, and nothing is read from the host except this directory.
#
# Base digests are the single source of truth also recorded in lab/DIGESTS.txt.
# Change a digest here and lab/verify.sh fails, which is the intended behaviour:
# re-pinning must be a deliberate, documented act (see lab/README.md).

FROM docker.io/library/golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

WORKDIR /src

# Dependencies first. This module has none outside the standard library, so the
# layer invalidates only when go.mod changes.
COPY go.mod ./
RUN go mod download

COPY . .

# Static, reproducible compile:
#   CGO_ENABLED=0  -> no libc, so the binary is independent of the runtime base
#   -trimpath      -> no build-machine paths in the binary
#   -buildid=      -> no toolchain build id, so the output is byte-stable
#   -ldflags -s -w -> symbols stripped, smaller image
#   -vcs=false     -> no git metadata required (the lab is not a checkout)
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/origin .

FROM docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS runtime

LABEL org.opencontainers.image.title="xammu-lab-origin" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="XAMMU laboratory origin: the simulated application behind the lab WAF. A test fixture with deliberate, documented behaviours. Not a security benchmark." \
      ai.xammu.lab.role="origin" \
      ai.xammu.lab.behaviors="B5-undetermined-area,B3-uninspected-vectors" \
      ai.xammu.lab.not-a-benchmark="true" \
      ai.xammu.lab.status="not_evaluated"

COPY --from=build /out/origin /usr/local/bin/xammu-lab-origin

# 65534:65534 is alpine's pre-existing nobody:nobody pair. Using it means no
# user is created at build time and the container cannot write /etc/passwd,
# which matters because the root filesystem is mounted read-only.
USER 65534:65534

ENV ORIGIN_LISTEN_ADDR=":8081"

EXPOSE 8081

HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=20 \
  CMD wget -q -O /dev/null http://127.0.0.1:8081/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/xammu-lab-origin"]
