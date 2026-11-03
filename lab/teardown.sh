#!/usr/bin/env bash
# teardown.sh -- stop and remove the XAMMU laboratory. Idempotent: it succeeds
# whether the lab is running, partially running, or already gone.
#
# It removes containers, the compose project and the isolated network. Images are
# kept by default so ./verify.sh can re-run without a rebuild; pass --rmi to
# remove them too, in which case ./build.sh must run again before ./verify.sh
# (DIGESTS.txt would otherwise describe images that no longer exist).
set -uo pipefail

LAB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$LAB_DIR/compose.yaml"
PROJECT="xammu-lab"
NETWORK="xammu-lab-net"
CONTAINERS=(xammu-lab-origin xammu-lab-waf xammu-lab-waf-stripped xammu-lab-netrunner)
IMAGES=(xammu-lab-origin:1.0.0 xammu-lab-waf:1.0.0)

RMI=0
[ "${1:-}" = "--rmi" ] && RMI=1

log() { printf '\033[1;35m[teardown]\033[0m %s\n' "$*"; }

if ! command -v docker >/dev/null 2>&1; then
  log "docker is not on PATH; nothing to tear down"
  exit 0
fi

log "stopping compose project '$PROJECT'"
docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true

# Belt and braces: remove by container name in case the project label changed,
# and by network name in case compose never got far enough to label it.
for c in "${CONTAINERS[@]}"; do
  docker rm -f "$c" >/dev/null 2>&1 || true
done
docker network rm "$NETWORK" >/dev/null 2>&1 || true

if [ "$RMI" = "1" ]; then
  log "removing lab images (--rmi)"
  for i in "${IMAGES[@]}"; do
    docker rmi -f "$i" >/dev/null 2>&1 || true
  done
fi

# Report, do not assume. Anything left over is named so the operator can act.
left_containers="$(docker ps -aq --filter name=xammu-lab- 2>/dev/null | grep -c . || true)"
left_networks="$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -c "^${NETWORK}\$" || true)"
left_images=""
if [ "$RMI" = "1" ]; then
  left_images="$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -c '^xammu-lab-' || true)"
fi

if [ "$left_containers" = "0" ] && [ "$left_networks" = "0" ]; then
  log "clean: 0 lab containers, 0 lab network${RMI:+, images removed=$left_images}"
  exit 0
fi

log "WARNING leftovers detected"
[ "$left_containers" != "0" ] && docker ps -a --filter name=xammu-lab- --format '  container {{.Names}} {{.Status}}'
[ "$left_networks" != "0" ] && echo "  network $NETWORK still exists"
exit 1
