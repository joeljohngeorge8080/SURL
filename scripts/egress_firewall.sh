#!/usr/bin/env bash
# Block the SURL container (docker-compose network surl_net, 172.28.0.0/24)
# from reaching private, loopback, link-local and cloud-metadata addresses.
# Defence in depth for the Chromium sandbox: the app already refuses private
# targets, but a redirect/DNS-rebind bug must not reach internal services.
#
# Run on the Docker HOST as root:  sudo scripts/egress_firewall.sh [apply|remove]
# Rules live in DOCKER-USER (evaluated before Docker's own rules). Not persistent
# across reboots; persist with iptables-persistent or a systemd unit if needed.
set -euo pipefail

SUBNET="${SURL_SUBNET:-172.28.0.0/24}"
BLOCKED=(
  10.0.0.0/8 172.16.0.0/12 192.168.0.0/16   # RFC1918
  127.0.0.0/8 169.254.0.0/16                # loopback, link-local (incl. 169.254.169.254)
  100.64.0.0/10 0.0.0.0/8                   # CGNAT, "this" network
)
action="${1:-apply}"

for dst in "${BLOCKED[@]}"; do
  rule=(DOCKER-USER -s "$SUBNET" -d "$dst" -j DROP)
  case "$action" in
    apply)  iptables -C "${rule[@]}" 2>/dev/null || iptables -I "${rule[@]}" ;;
    remove) iptables -C "${rule[@]}" 2>/dev/null && iptables -D "${rule[@]}" || true ;;
    *) echo "usage: $0 [apply|remove]" >&2; exit 2 ;;
  esac
done
echo "egress rules ${action}d for ${SUBNET}"
