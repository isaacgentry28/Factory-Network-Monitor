#!/usr/bin/env bash
# edge/install.sh - one-time setup for the Sense HAT Pi (NFR-6.4)
#
# Run from anywhere inside the repo:   sudo ./edge/install.sh
#
# Installs packages, installs the systemd units (grouped under cps-edge.target),
# and enables them so every edge component starts at boot with no manual steps.
# Safe to run again after a git pull (it just re-copies the units).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo ./edge/install.sh" >&2
  exit 1
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="${SUDO_USER:-pi}"
UNIT_DIR=/etc/systemd/system

echo "Repo:      $REPO"
echo "Run as:    $RUN_USER (enforcement agent runs as root)"

echo "== Installing packages"
apt-get update -qq
apt-get install -y sense-hat nftables python3

echo "== Giving $RUN_USER access to the Sense HAT (I2C sensors, joystick, LED framebuffer)"
for g in i2c input video gpio; do
  getent group "$g" >/dev/null && usermod -aG "$g" "$RUN_USER"
done

echo "== Installing systemd units"
cp "$REPO/edge/systemd/cps-edge.target" "$UNIT_DIR/"
for unit in "$REPO"/edge/systemd/cps-*.service; do
  sed -e "s|@REPO@|$REPO|g" -e "s|@USER@|$RUN_USER|g" "$unit" > "$UNIT_DIR/$(basename "$unit")"
done

systemctl daemon-reload
systemctl enable systemd-networkd-wait-online.service NetworkManager-wait-online.service 2>/dev/null || true
systemctl enable cps-edge.target
for unit in "$REPO"/edge/systemd/cps-*.service; do
  systemctl enable "$(basename "$unit")"
done

echo "== Starting"
systemctl restart cps-edge.target
sleep 2
systemctl --no-pager --plain list-units 'cps-*'

cat <<EOF

Done. Useful commands:
  systemctl status 'cps-*'                 # are they all running?
  journalctl -u cps-enforce -f             # live log of one component
  sudo systemctl restart cps-edge.target   # restart everything after a git pull
  sudo systemctl stop cps-edge.target      # stop everything
  sudo nft delete table inet cps_quarantine   # EMERGENCY: remove all quarantine rules
EOF