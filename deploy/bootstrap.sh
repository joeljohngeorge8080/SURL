#!/usr/bin/env bash
# One-time (idempotent) setup of a fresh Ubuntu EC2 instance for SURL.
# Run as the ubuntu user from the cloned repo:
#   DOMAIN=sentinelurl.site CERT_EMAIL=you@example.com ./deploy/bootstrap.sh
# Set SKIP_TLS=1 to configure HTTP only (e.g. before DNS points at the host).
set -euo pipefail

: "${DOMAIN:?set DOMAIN, e.g. DOMAIN=sentinelurl.site}"
PORT="${API_PORT:-8001}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

[ -f .env ] || { echo "Create $REPO_DIR/.env first (cp .env.example .env, add keys)."; exit 1; }

# 1. Swap: Chromium on a 1 GB host needs it.
if ! swapon --show | grep -q /swapfile; then
  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi

# 2. Packages
sudo apt-get update -qq
sudo apt-get install -y -qq docker.io docker-compose-v2 nginx certbot python3-certbot-nginx
sudo usermod -aG docker "$USER"

# 3. Production env values behind the proxy
set_env() { grep -q "^$1=" .env && sed -i "s|^$1=.*|$1=$2|" .env || echo "$1=$2" >> .env; }
set_env API_PORT "$PORT"
set_env TRUST_PROXY_HEADERS True
set_env CORS_ORIGINS "https://$DOMAIN"

# 4. nginx
sed -e "s|__DOMAIN__|$DOMAIN|g" -e "s|__PORT__|$PORT|g" deploy/nginx/surl.conf \
  | sudo tee /etc/nginx/sites-available/surl >/dev/null
sudo ln -sf /etc/nginx/sites-available/surl /etc/nginx/sites-enabled/surl
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# 5. systemd: egress firewall + auto-deploy timer
sudo cp deploy/systemd/surl-*.service deploy/systemd/surl-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now surl-egress.service surl-deploy.timer

# 6. TLS (needs DNS A record -> this host and ports 80/443 open)
if [ "${SKIP_TLS:-0}" != 1 ]; then
  sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect \
    -m "${CERT_EMAIL:?set CERT_EMAIL for Lets Encrypt}"
fi

echo "Done. First image pull happens within a minute: journalctl -u surl-deploy -f"
