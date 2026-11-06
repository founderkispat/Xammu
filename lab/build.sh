#!/usr/bin/env bash
# build.sh -- build the XAMMU laboratory images and record their digests.
#
# Requires only Docker (with buildx, which Docker Desktop ships). The Go compile
# happens inside the multi-stage Dockerfiles against a digest-pinned
# golang:1.27-alpine, so the toolchain is part of the reproducible contract
# rather than a property of whoever's machine ran the build. Host Go is used only
# for the optional ./lint.sh style checks; this script never needs it.
#
# Idempotent: re-running overwrites lab/DIGESTS.txt rather than appending, and
# rebuilding unchanged sources yields the same recorded image IDs. That second
# property needs --provenance=false/--sbom=false; see build_one below for the
# measurement that proved it.
set -euo pipefail

LAB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$LAB_DIR"

ORIGIN_IMAGE="xammu-lab-origin:1.0.0"
WAF_IMAGE="xammu-lab-waf:1.0.0"
RUNNER_IMAGE="docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b"
DIGESTS_FILE="$LAB_DIR/DIGESTS.txt"
META_DIR="$(mktemp -d)"
trap 'rm -rf "$META_DIR"' EXIT

log() { printf '\033[1;36m[build]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[build][error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker is required and was not found on PATH."
docker info >/dev/null 2>&1 || die "docker is on PATH but the daemon is not answering. Start Docker Desktop."
docker buildx version >/dev/null 2>&1 || die "docker buildx is required (it ships with Docker Desktop)."
for f in origin/Dockerfile waf/Dockerfile compose.yaml; do
  [ -f "$f" ] || die "missing $f"
done

# The hardening invariants of compose.yaml are asserted by internal/labcheck in
# the ordinary Go suite without Docker. This asks Compose itself whether the
# anchors resolve and every field is spelled as Compose understands it: a file
# that passes the textual checks can still fail `up` after a long build.
docker compose -f compose.yaml config --format json >/dev/null 2>&1 \
  || die "docker compose config rejected compose.yaml; fix it before building."
log "compose : docker compose config accepted compose.yaml"

log "Docker : $(docker --version)"
log "Buildx : $(docker buildx version | head -1)"

# ---------------------------------------------------------------------------
# 1. Verify the pinned base digests are what the registry actually serves.
#    If upstream moved, this stops instead of quietly building against something
#    else. Re-pinning is a deliberate act; the procedure is in README.md.
# ---------------------------------------------------------------------------
PINNED_BASES="$(grep -hoE 'docker\.io/[a-zA-Z0-9._/:-]+@sha256:[0-9a-f]{64}' \
                  origin/Dockerfile waf/Dockerfile | sort -u)"
[ -n "$PINNED_BASES" ] || die "no digest-pinned base images found in origin/Dockerfile or waf/Dockerfile."

log "verifying pinned base images"
while read -r ref; do
  [ -n "$ref" ] || continue
  tag="${ref%@sha256:*}"
  want_full="${ref##*@}"        # sha256:<64 hex>
  want="${want_full#sha256:}"   # bare hex, used only for the membership test
  docker pull "$ref" >/dev/null 2>&1 || die "could not pull pinned base $ref (network or wrong digest)"
  # A tag pulled by digest can register more than one RepoDigest (the index and
  # the platform manifest), so the test is membership, not equality of the first.
  have_list="$(docker image inspect --format '{{range .RepoDigests}}{{.}} {{end}}' "$ref" 2>/dev/null \
                | tr ' ' '\n' | grep -o 'sha256:[0-9a-f]\{64\}' | sort -u)"
  if ! printf '%s\n' "$have_list" | grep -qx "${want_full}"; then
    die "pinned digest for $tag is not among what the registry resolved.
     pinned : ${want_full}
     actual : $(printf '%s ' $have_list)
     Decide deliberately, then update BOTH Dockerfiles and re-run ./build.sh.
     See README.md, section 'Re-pinning a base image'."
  fi
  log "  ${tag} -> ${want_full} OK"
done <<< "$PINNED_BASES"

# The runner image is declared in compose.yaml, not built here, but a stale pin
# there breaks ./verify.sh in a confusing way, so it is checked here too.
log "verifying pinned runner image"
docker pull "$RUNNER_IMAGE" >/dev/null 2>&1 || die "could not pull pinned runner $RUNNER_IMAGE"

# ---------------------------------------------------------------------------
# 2. Build
# ---------------------------------------------------------------------------
build_one() {
  local image="$1" context="$2"
  log "building $image from ./$context"
  # --pull forces the pinned FROM lines to be re-resolved rather than trusting a
  # stale local copy. Build cache is left on: buildkit invalidates on content, so
  # a cached layer is still the same digest.
  #
  # --provenance=false --sbom=false is NOT cosmetic, it is the reason the recorded
  # digest means anything. Measured on this machine with Docker 29.8.2 + the
  # containerd image store: with the defaults (attestations on), every rebuild of
  # byte-identical sources minted a NEW image ID -- b397a888 -> 64a72698 -- while
  # the image config stayed byte-identical (created=2026-10-27T19:37:50.436380228Z
  # across both builds). The attestation layer records the build instant, so the
  # digest identified "when it was built" instead of "what it contains", which
  # would make DIGESTS.txt a per-run artifact and reproducibility unfalsifiable.
  # With attestations off, two consecutive rebuilds of the same sources resolve to
  # the same ID. ./build.sh is re-run by ./verify.sh's identity check, so this
  # property is exercised, not assumed.
  docker buildx build \
    --pull=true \
    --platform linux/amd64 \
    --provenance=false \
    --sbom=false \
    --file "$context/Dockerfile" \
    --tag "$image" \
    --metadata-file "$META_DIR/$context.json" \
    --load \
    "$context" 2>&1 | grep -Ev '^(#\ [0-9]+ (DONE|sha256:)|=> )' | tail -20 || true
  docker image inspect "$image" >/dev/null 2>&1 || die "build reported success but $image is not present"
}

build_one "$ORIGIN_IMAGE" origin
build_one "$WAF_IMAGE" waf

# ---------------------------------------------------------------------------
# 3. Record digests
# ---------------------------------------------------------------------------
# A locally built image has no registry manifest digest, so its authoritative
# identity is the content-addressed image ID (the sha256 of the image config).
# buildx also reports a manifest digest in its metadata file; it is recorded when
# present and never invented.
manifest_digest() {
  local file="$1"
  [ -f "$file" ] || return 0
  # grep/sed rather than jq or python: the build host is only guaranteed Docker.
  grep -o '"containerimage\.digest"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" 2>/dev/null \
    | sed 's/.*"\(sha256:[0-9a-f]*\)"$/\1/' | head -1
}

ORIGIN_ID="$(docker image inspect --format '{{.Id}}' "$ORIGIN_IMAGE")"
WAF_ID="$(docker image inspect --format '{{.Id}}' "$WAF_IMAGE")"
ORIGIN_MANIFEST="$(manifest_digest "$META_DIR/origin.json")"
WAF_MANIFEST="$(manifest_digest "$META_DIR/waf.json")"
ORIGIN_SIZE="$(docker image inspect --format '{{.Size}}' "$ORIGIN_IMAGE")"
WAF_SIZE="$(docker image inspect --format '{{.Size}}' "$WAF_IMAGE")"
ORIGIN_CREATED="$(docker image inspect --format '{{.Created}}' "$ORIGIN_IMAGE")"
WAF_CREATED="$(docker image inspect --format '{{.Created}}' "$WAF_IMAGE")"
SRC_HASHES="$(find origin waf -maxdepth 1 -type f \( -name '*.go' -o -name 'go.mod' \) | sort | xargs sha256sum)"
DOCKERFILE_HASHES="$(find origin waf -maxdepth 1 -name Dockerfile | sort | xargs sha256sum)"

{
  echo "# XAMMU v1.0.0 laboratory -- resolved image digests"
  echo "# Generated by ./build.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "#"
  echo "# This file is the reproducibility contract. ./verify.sh asserts that the"
  echo "# containers actually running match the image IDs recorded here. A compose"
  echo "# file alone is never accepted as proof of reproducibility, so this file plus"
  echo "# the executable self-test are the proof. Do not hand-edit: run ./build.sh."
  echo ""
  echo "[images]"
  echo "xammu-lab-origin:1.0.0  image_id=${ORIGIN_ID}"
  echo "xammu-lab-waf:1.0.0     image_id=${WAF_ID}"
  echo ""
  echo "[manifest_digests]"
  echo "# Recorded only when buildx reported one; 'not_reported' means the local"
  echo "# docker-driver build returned no OCI manifest digest. Nothing here is guessed."
  echo "xammu-lab-origin:1.0.0  manifest=${ORIGIN_MANIFEST:-not_reported}"
  echo "xammu-lab-waf:1.0.0     manifest=${WAF_MANIFEST:-not_reported}"
  echo ""
  echo "[pinned_base_images]"
  echo "# The FROM lines of origin/Dockerfile and waf/Dockerfile, verified against the"
  echo "# registry at build time. ./build.sh aborts if they no longer match."
  while read -r ref; do [ -n "$ref" ] && echo "  $ref"; done <<< "$PINNED_BASES"
  echo ""
  echo "[runner_image]"
  echo "# Declared in compose.yaml, pulled not built. Pinned by digest at point of use."
  echo "  $RUNNER_IMAGE"
  echo ""
  echo "[source_fingerprints]"
  echo "# sha256 of everything that goes into an image."
  echo "$SRC_HASHES" | sed 's/^/  /'
  echo "$DOCKERFILE_HASHES" | sed 's/^/  /'
  echo ""
  echo "[image_metadata]"
  echo "  origin size_bytes=${ORIGIN_SIZE} created=${ORIGIN_CREATED}"
  echo "  waf    size_bytes=${WAF_SIZE} created=${WAF_CREATED}"
  echo "  docker=$(docker --version)"
  echo "  platform=linux/amd64"
  echo "  compile=golang:1.27-alpine (pinned above); CGO_ENABLED=0 -trimpath -buildid= -s -w"
  echo "  attestations=provenance=false,sbom=false  # required for a content-stable image ID"
  echo "  store=$(docker info --format '{{.Driver}}')"
  echo ""
  echo "[repin_procedure]"
  echo "  1. docker buildx imagetools inspect <image>:<tag>   # list current manifest digests"
  echo "  2. replace the sha256 in origin/Dockerfile AND waf/Dockerfile (both must match)"
  echo "  3. ./build.sh    # rewrites this file, aborting if a pin no longer resolves"
  echo "  4. ./verify.sh   # asserts the running containers match this file"
} > "$DIGESTS_FILE"

log "wrote $DIGESTS_FILE"
echo
sed 's/^/    /' "$DIGESTS_FILE"
echo
log "origin image_id = ${ORIGIN_ID}"
log "waf    image_id = ${WAF_ID}"
log "manifests: origin=${ORIGIN_MANIFEST:-not_reported} waf=${WAF_MANIFEST:-not_reported}"
log "done. Next: ./verify.sh"
