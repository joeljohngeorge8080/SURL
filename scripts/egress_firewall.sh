#!/usr/bin/env bash
# Block the SURL container (docker-compose network surl_net, 172.30.0.0/24)
# from reaching private, loopback, link-local and cloud-metadata addresses.
# Defence in depth for the Chromium sandbox: the app already refuses private
# targets, but a redirect/DNS-rebind bug must not reach internal services.
#
# Run on the Docker HOST as root:  sudo scripts/egress_firewall.sh [apply|remove]
# Rules live in DOCKER-USER (evaluated before Docker's own rules). Not persistent
# across reboots; persist with iptables-persistent or a systemd unit if needed.
set -euo pipefail

SUBNET="${SURL_SUBNET:-172.30.0.0/24}"
BLOCKED=(
  10.0.0.0/8 172.16.0.0/12 192.168.0.0/16   # RFC1918
  127.0.0.0/8 169.254.0.0/16                # loopback, link-local (incl. 169.254.169.254)
  100.64.0.0/10 0.0.0.0/8                   # CGNAT, "this" network
)
action="${1:-apply}"

case "$action" in apply|remove) ;; *) echo "usage: $0 [apply|remove]" >&2; exit 2 ;; esac

ensure() {  # ensure <apply|remove> <iptables rule...>
  local mode="$1"; shift
  if [ "$mode" = apply ]; then
    iptables -C "$@" 2>/dev/null || iptables -I "$@"
  else
    if iptables -C "$@" 2>/dev/null; then iptables -D "$@"; fi
  fi
}

for dst in "${BLOCKED[@]}"; do
  ensure "$action" DOCKER-USER -s "$SUBNET" -d "$dst" -j DROP
done

# DNS: Docker's embedded resolver forwards external lookups from inside the
# container's network namespace. On EC2 the upstream is the VPC resolver
# (e.g. 172.31.0.2 or 169.254.169.253), which sits inside the blocked ranges, so
# without this every lookup from the container fails. Allow port 53 to exactly
# the host's upstream resolvers. Inserted after the DROPs so it lands above them.
UPSTREAM_RESOLV="${SURL_RESOLV_CONF:-/run/systemd/resolve/resolv.conf}"
[ -r "$UPSTREAM_RESOLV" ] || UPSTREAM_RESOLV=/etc/resolv.conf
mapfile -t RESOLVERS < <(awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ && $2 !~ /^127\./ {print $2}' "$UPSTREAM_RESOLV")
for ns in "${RESOLVERS[@]}"; do
  for proto in udp tcp; do
    ensure "$action" DOCKER-USER -s "$SUBNET" -d "$ns/32" -p "$proto" --dport 53 -j ACCEPT
  done
done
case "$action" in apply) verb=applied ;; *) verb=removed ;; esac
echo "egress rules ${verb} for ${SUBNET} (DNS allowed to: ${RESOLVERS[*]:-none})"
