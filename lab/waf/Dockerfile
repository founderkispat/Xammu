# XAMMU laboratory WAF.
#
# Same pinned builder and runtime bases as the origin service, so one Docker
# installation is enough to rebuild the whole lab. See lab/README.md for the
# digest-repinning procedure; lab/verify.sh asserts these digests at runtime.

FROM docker.io/library/golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .

RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/waf .

FROM docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS runtime

LABEL org.opencontainers.image.title="xammu-lab-waf" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="XAMMU laboratory WAF: a reverse proxy with a documented, deliberately incomplete rule table. A test fixture with known gaps. Not a security control and not a benchmark of commercial WAFs." \
      ai.xammu.lab.role="waf" \
      ai.xammu.lab.behaviors="B1-vector-gap,B2-encoding-bypass,B3-uninspected-vectors,B4-over-blocking,B5-undetermined-area" \
      ai.xammu.lab.not-a-benchmark="true" \
      ai.xammu.lab.status="not_evaluated"

COPY --from=build /out/waf /usr/local/bin/xammu-lab-waf

USER 65534:65534

# Defaults match lab/compose.yaml. Every one of them is asserted by
# lab/verify.sh, so a silently different container cannot pass the self-test.
ENV WAF_LISTEN_ADDR=":8080" \
    WAF_ORIGIN_URL="http://origin:8081" \
    LAB_STRIP_WAF_MARKER_HEADERS="0" \
    LAB_STRIP_WAF_TRACE_HEADERS="0"

EXPOSE 8080

# /__lab/info answers 200 and only exists on the WAF, so the health probe never
# depends on the origin and never resembles a business response.
HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=20 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/__lab/info || exit 1

ENTRYPOINT ["/usr/local/bin/xammu-lab-waf"]
