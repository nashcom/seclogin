#!/bin/bash
# Show seclogin syslog entries
# Usage: ./show_syslog.sh [journalctl options]
#   ./show_syslog.sh          — last 20 entries
#   ./show_syslog.sh -f       — follow live
#   ./show_syslog.sh --since today
journalctl -t seclogin -t seclogin-srv -n 20 "$@"
