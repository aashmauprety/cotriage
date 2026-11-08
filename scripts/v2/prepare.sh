#!/bin/sh
# Label alerts, build cases and the tool index for the given AIT-LDS v2 scenarios.
cd "$(dirname "$0")/../.."
for s in "$@"; do
  python3 -I scripts/v2/label_alerts.py "$s" > "alerts_v2/${s}_labels.txt" && \
  python3 -I scripts/v2/make_cases_v2.py "$s" > "alerts_v2/${s}_cases.txt" && \
  python3 -I scripts/v2/index_v2.py "$s" && head -1 "alerts_v2/${s}_cases.txt"
done
