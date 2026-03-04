#!/usr/bin/env python3
"""Load panel.env and start Flask app. Run as root."""

import os
import sys

config_env = os.environ.get("DNSTT_PANEL_ENV", "/etc/dnstt/panel.env")
if os.path.isfile(config_env):
    with open(config_env) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()

# Ensure we look for app in the panel directory
base = os.environ.get("DNSTT_PANEL_BASE", "/opt/dnstt-panel")
sys.path.insert(0, base)
os.chdir(base)

from app import main

if __name__ == "__main__":
    main()
