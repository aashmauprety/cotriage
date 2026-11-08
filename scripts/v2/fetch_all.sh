#!/bin/sh
# Fetch server logs and labels of every AIT-LDS v2 scenario (no pcaps, no user/attacker hosts).
cd "$(dirname "$0")/../.."
PAT='^(labels/(?!monitoring/)|gather/(?!(attacker|internal_employee|remote_employee|ext_user|monitoring))[^/]+/logs/(?!journal/)(?!.*(pcap|traffic\.json)))'
for s in "$@"; do
  python3 -I scripts/v2/remote_zip.py get "$s" "AIT-LDS-v2/$s" "$PAT" > "AIT-LDS-v2/${s}_fetch.log" 2>&1 \
    && echo "$s ok $(du -sh AIT-LDS-v2/$s | cut -f1)" || echo "$s FAILED (see AIT-LDS-v2/${s}_fetch.log)"
done
