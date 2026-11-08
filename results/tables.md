# Results: alert triage with tool ladders

Balanced accuracy = (attacks caught rate + correct-normal rate) / 2. Cost = API cost per 1,000 alerts (qwen runs locally: $0). Values are means over repeated runs where available (column `runs`).

## Setting A (25 attack / 564 normal alerts)

| model | condition | runs | caught | false alarms | balanced acc. | $ per 1k alerts | s/alert | step gain (pp) | pp per extra $ |
|---|---|---|---|---|---|---|---|---|---|
| qwen2.5-14B (local) | L0_none | 1 | 12.0/25 | 218.0/564 | 0.547 | 0.00 | 9.2 |  |  |
| qwen2.5-14B (local) | L1_history | 1 | 11.0/25 | 95.0/564 | 0.636 | 0.00 | 7.2 | +8.9 | ≈ free |
| qwen2.5-14B (local) | L2_+suricata | 1 | 12.0/25 | 142.0/564 | 0.614 | 0.00 | 7.5 | -2.2 |  |
| qwen2.5-14B (local) | L3_+ip | 1 | 14.0/25 | 1.0/564 | 0.779 | 0.00 | 16.4 | +16.5 | ≈ free |
| qwen2.5-14B (local) | L4_+audit | 1 | 15.0/25 | 0.0/564 | 0.800 | 0.00 | 12.0 | +2.1 | ≈ free |
| qwen2.5-14B (local) | only_suricata | 1 | 15.0/25 | 256.0/564 | 0.573 | 0.00 | 7.5 |  |  |
| qwen2.5-14B (local) | only_ip | 1 | 15.0/25 | 2.0/564 | 0.798 | 0.00 | 16.0 |  |  |
| qwen2.5-14B (local) | only_audit | 1 | 9.0/25 | 39.0/564 | 0.645 | 0.00 | 11.5 |  |  |
| Claude Haiku 5.5 | L0_none | 3 | 9.3/25 | 0.0/564 | 0.687 | 0.25 | 2.2 |  |  |
| Claude Haiku 5.5 | L1_history | 3 | 14.3/25 | 3.0/564 | 0.784 | 0.26 | 2.2 | +9.7 | 815.2 |
| Claude Haiku 5.5 | L2_+suricata | 3 | 19.7/25 | 1.0/564 | 0.892 | 0.27 | 2.2 | +10.8 | 1002.8 |
| Claude Haiku 5.5 | L3_+ip | 3 | 24.0/25 | 2.3/564 | 0.978 | 0.38 | 2.1 | +8.5 | 83.6 |
| Claude Haiku 5.5 | L4_+audit | 3 | 25.0/25 | 3.0/564 | 0.997 | 0.46 | 2.3 | +1.9 | 21.7 |
| Claude Haiku 5.5 | only_suricata | 3 | 20.3/25 | 1.0/564 | 0.906 | 0.27 | 2.3 |  |  |
| Claude Haiku 5.5 | only_ip | 3 | 23.7/25 | 3.7/564 | 0.970 | 0.37 | 2.3 |  |  |
| Claude Haiku 5.5 | only_audit | 3 | 8.3/25 | 3.0/564 | 0.664 | 0.36 | 2.5 |  |  |
| Claude Opus 5.5 | L0_none | 3 | 18.7/25 | 0.7/564 | 0.873 | 6.79 | 3.2 |  |  |
| Claude Opus 5.5 | L1_history | 3 | 21.7/25 | 4.3/564 | 0.929 | 6.76 | 2.9 | +5.7 | ≈ free |
| Claude Opus 5.5 | L2_+suricata | 3 | 21.3/25 | 4.0/564 | 0.923 | 7.15 | 2.8 | -0.6 | -1.6 |
| Claude Opus 5.5 | L3_+ip | 3 | 23.7/25 | 2.0/564 | 0.972 | 11.06 | 2.6 | +4.8 | 1.2 |
| Claude Opus 5.5 | L4_+audit | 3 | 23.3/25 | 2.3/564 | 0.965 | 14.19 | 2.6 | -0.7 | -0.2 |
| Claude Opus 5.5 | only_suricata | 3 | 22.0/25 | 1.0/564 | 0.939 | 6.58 | 2.8 |  |  |
| Claude Opus 5.5 | only_ip | 3 | 24.0/25 | 1.3/564 | 0.979 | 10.12 | 2.6 |  |  |
| Claude Opus 5.5 | only_audit | 3 | 16.7/25 | 8.7/564 | 0.826 | 8.65 | 2.5 |  |  |

## Setting B30 (27 attack / 28 normal alerts)

| model | condition | runs | caught | false alarms | balanced acc. | $ per 1k alerts | s/alert | step gain (pp) | pp per extra $ |
|---|---|---|---|---|---|---|---|---|---|
| qwen2.5-14B (local) | V0_none | 1 | 0.0/27 | 0.0/28 | 0.500 | 0.00 | 26.1 |  |  |
| qwen2.5-14B (local) | V1_overview | 1 | 24.0/27 | 1.0/28 | 0.927 | 0.00 | 34.9 | +42.7 | ≈ free |
| qwen2.5-14B (local) | V2_+suricata | 1 | 25.0/27 | 7.0/28 | 0.838 | 0.00 | 14.2 | -8.9 |  |
| qwen2.5-14B (local) | V3_+ip | 1 | 23.0/27 | 1.0/28 | 0.908 | 0.00 | 30.6 | +7.0 | ≈ free |
| qwen2.5-14B (local) | V4_+audit | 1 | 22.0/27 | 0.0/28 | 0.907 | 0.00 | 21.2 | -0.1 |  |
| qwen2.5-14B (local) | only_ip | 1 | 22.0/27 | 1.0/28 | 0.890 | 0.00 | 23.5 |  |  |
| qwen2.5-14B (local) | only_audit | 1 | 0.0/27 | 0.0/28 | 0.500 | 0.00 | 12.7 |  |  |
| Claude Haiku 5.5 | V0_none | 3 | 0.0/27 | 0.0/28 | 0.500 | 0.15 | 1.4 |  |  |
| Claude Haiku 5.5 | V1_overview | 3 | 23.0/27 | 0.0/28 | 0.926 | 0.21 | 1.8 | +42.6 | 646.3 |
| Claude Haiku 5.5 | V2_+suricata | 3 | 23.0/27 | 0.0/28 | 0.926 | 0.25 | 2.0 | +0.0 | 0.0 |
| Claude Haiku 5.5 | V3_+ip | 3 | 23.0/27 | 1.0/28 | 0.908 | 0.45 | 2.1 | -1.8 | -8.8 |
| Claude Haiku 5.5 | V4_+audit | 3 | 23.0/27 | 1.0/28 | 0.908 | 0.58 | 2.3 | +0.0 | 0.0 |
| Claude Haiku 5.5 | only_ip | 3 | 23.0/27 | 1.0/28 | 0.908 | 0.39 | 1.8 |  |  |
| Claude Haiku 5.5 | only_audit | 3 | 4.0/27 | 0.3/28 | 0.568 | 0.32 | 2.1 |  |  |
| Claude Opus 5.5 | V0_none | 3 | 1.3/27 | 0.0/28 | 0.525 | 8.37 | 4.7 |  |  |
| Claude Opus 5.5 | V1_overview | 3 | 23.0/27 | 0.0/28 | 0.926 | 8.51 | 4.1 | +40.1 | 276.7 |
| Claude Opus 5.5 | V2_+suricata | 3 | 23.0/27 | 0.0/28 | 0.926 | 8.76 | 3.9 | +0.0 | 0.0 |
| Claude Opus 5.5 | V3_+ip | 3 | 23.0/27 | 0.0/28 | 0.926 | 15.52 | 3.4 | +0.0 | 0.0 |
| Claude Opus 5.5 | V4_+audit | 3 | 23.0/27 | 1.0/28 | 0.908 | 20.33 | 3.6 | -1.8 | -0.4 |
| Claude Opus 5.5 | only_ip | 3 | 24.0/27 | 0.0/28 | 0.944 | 14.21 | 3.5 |  |  |
| Claude Opus 5.5 | only_audit | 3 | 7.0/27 | 2.0/28 | 0.594 | 11.74 | 4.1 |  |  |

## Setting B5 (27 attack / 28 normal alerts)

| model | condition | runs | caught | false alarms | balanced acc. | $ per 1k alerts | s/alert | step gain (pp) | pp per extra $ |
|---|---|---|---|---|---|---|---|---|---|
| qwen2.5-14B (local) | V0_none | 1 | 0.0/27 | 0.0/28 | 0.500 | 0.00 | 5.9 |  |  |
| qwen2.5-14B (local) | V1_overview | 1 | 19.0/27 | 0.0/28 | 0.852 | 0.00 | 8.6 | +35.2 | ≈ free |
| qwen2.5-14B (local) | V2_+suricata | 1 | 22.0/27 | 1.0/28 | 0.890 | 0.00 | 7.2 | +3.8 | ≈ free |
| qwen2.5-14B (local) | V3_+ip | 1 | 21.0/27 | 0.0/28 | 0.889 | 0.00 | 23.9 | -0.1 |  |
| qwen2.5-14B (local) | V4_+audit | 1 | 22.0/27 | 0.0/28 | 0.907 | 0.00 | 13.1 | +1.9 | ≈ free |
| qwen2.5-14B (local) | only_ip | 1 | 19.0/27 | 1.0/28 | 0.834 | 0.00 | 22.8 |  |  |
| qwen2.5-14B (local) | only_audit | 1 | 5.0/27 | 0.0/28 | 0.593 | 0.00 | 11.5 |  |  |
| Claude Haiku 5.5 | V0_none | 3 | 0.0/27 | 0.0/28 | 0.500 | 0.14 | 1.3 |  |  |
| Claude Haiku 5.5 | V1_overview | 3 | 19.0/27 | 0.0/28 | 0.852 | 0.19 | 1.5 | +35.2 | 781.1 |
| Claude Haiku 5.5 | V2_+suricata | 3 | 19.0/27 | 0.0/28 | 0.852 | 0.22 | 1.8 | +0.0 | 0.0 |
| Claude Haiku 5.5 | V3_+ip | 3 | 22.0/27 | 0.7/28 | 0.896 | 0.43 | 2.1 | +4.4 | 21.1 |
| Claude Haiku 5.5 | V4_+audit | 3 | 23.0/27 | 0.7/28 | 0.914 | 0.53 | 2.3 | +1.9 | 19.1 |
| Claude Haiku 5.5 | only_ip | 3 | 22.0/27 | 1.0/28 | 0.890 | 0.37 | 1.8 |  |  |
| Claude Haiku 5.5 | only_audit | 3 | 6.0/27 | 0.0/28 | 0.611 | 0.28 | 1.9 |  |  |
| Claude Opus 5.5 | V0_none | 3 | 0.0/27 | 0.0/28 | 0.500 | 7.92 | 4.4 |  |  |
| Claude Opus 5.5 | V1_overview | 3 | 22.7/27 | 0.0/28 | 0.920 | 7.34 | 3.6 | +42.0 | ≈ free |
| Claude Opus 5.5 | V2_+suricata | 3 | 23.0/27 | 0.0/28 | 0.926 | 7.75 | 3.6 | +0.6 | 1.5 |
| Claude Opus 5.5 | V3_+ip | 3 | 22.7/27 | 0.0/28 | 0.920 | 14.87 | 3.6 | -0.6 | -0.1 |
| Claude Opus 5.5 | V4_+audit | 3 | 23.0/27 | 1.0/28 | 0.908 | 17.59 | 3.2 | -1.2 | -0.4 |
| Claude Opus 5.5 | only_ip | 3 | 23.0/27 | 0.0/28 | 0.926 | 13.53 | 3.6 |  |  |
| Claude Opus 5.5 | only_audit | 3 | 8.0/27 | 1.0/28 | 0.630 | 9.90 | 3.6 |  |  |
