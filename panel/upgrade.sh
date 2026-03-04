#!/bin/bash
# Upgrade panel from repo archive. Run as root. Called by panel API.
# Env: DNSTT_PANEL_BASE, DNSTT_CONFIG_DIR, PANEL_ARCHIVE_URL (optional)

set -e
PANEL_INSTALL_DIR="${DNSTT_PANEL_BASE:-/opt/dnstt-panel}"
CONFIG_DIR="${DNSTT_CONFIG_DIR:-/etc/dnstt}"
PANEL_ARCHIVE_URL="${PANEL_ARCHIVE_URL:-https://github.com/begirkaro/dnstt-deploy/archive/refs/heads/main.tar.gz}"
LOG_FILE="${PANEL_INSTALL_DIR}/upgrade.log"
tmp_archive="/tmp/dnstt-panel-upgrade.tar.gz"
tmp_extract="/tmp/dnstt-panel-upgrade-extract"

log() { echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"; }

log "Upgrade started."
rm -rf "$tmp_extract"
mkdir -p "$tmp_extract"

if ! curl -sLf "$PANEL_ARCHIVE_URL" -o "$tmp_archive"; then
  log "ERROR: Failed to download $PANEL_ARCHIVE_URL"
  exit 1
fi

if ! tar -xzf "$tmp_archive" -C "$tmp_extract"; then
  log "ERROR: Failed to extract archive"
  rm -f "$tmp_archive"
  exit 1
fi

panel_src=$(find "$tmp_extract" -type d -name "panel" 2>/dev/null | head -1)
if [[ -z "$panel_src" || ! -f "$panel_src/app.py" ]]; then
  log "ERROR: Panel directory not found in archive"
  rm -rf "$tmp_extract" "$tmp_archive"
  exit 1
fi

# Copy files; do not overwrite venv or config
for f in app.py requirements.txt init_panel.py run_panel.py VERSION upgrade.sh; do
  if [[ -e "$panel_src/$f" ]]; then
    cp "$panel_src/$f" "$PANEL_INSTALL_DIR/"
    log "Updated $f"
  fi
done
if [[ -d "$panel_src/templates" ]]; then
  cp -r "$panel_src/templates" "$PANEL_INSTALL_DIR/"
  log "Updated templates/"
fi

rm -rf "$tmp_extract" "$tmp_archive"

# Reinstall dependencies
if [[ -x "$PANEL_INSTALL_DIR/venv/bin/pip" ]]; then
  "$PANEL_INSTALL_DIR/venv/bin/pip" install -q -r "$PANEL_INSTALL_DIR/requirements.txt" >> "$LOG_FILE" 2>&1 || true
elif command -v pip3 &>/dev/null; then
  pip3 install -q -r "$PANEL_INSTALL_DIR/requirements.txt" >> "$LOG_FILE" 2>&1 || true
fi

log "Restarting dnstt-panel..."
systemctl restart dnstt-panel 2>> "$LOG_FILE" || true
log "Upgrade finished."
