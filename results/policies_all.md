# Per-alert policies vs. fixed configurations (Setting A, 589 cases)

| policy | model | runs | detected /25 | false alarms /564 | balanced acc. | $ per 1k alerts | tool calls / alert | alerts using IP or audit (%) |
|---|---|---|---|---|---|---|---|---|
| fixed: L0_none | Haiku 5.5 | 3 | 9.3 | 0.0 | 68.7 | 0.25 | 0.00 | 0 |
| fixed: L3_+ip | Haiku 5.5 | 3 | 24.0 | 2.3 | 97.8 | 0.38 | 3.00 | 100 |
| fixed: L4_+audit | Haiku 5.5 | 3 | 25.0 | 3.0 | 99.7 | 0.46 | 4.00 | 100 |
| fixed: only_ip | Haiku 5.5 | 3 | 23.7 | 3.7 | 97.0 | 0.37 | 1.00 | 100 |
| P1 escalation [0.2,0.8] | Haiku 5.5 | 3 | 15.0 | 0.0 | 80.0 | 0.28 | 0.07 | 1 |
| P1 escalation [0.1,0.9] | Haiku 5.5 | 3 | 22.7 | 1.0 | 95.2 | 0.91 | 2.11 | 47 |
| P2 alert-type routing (LOHO) | Haiku 5.5 | 3 | 23.0 | 1.3 | 95.9 | 0.29 | 1.61 | 12 |
| P5 cost-aware stopping (lambda=0.0) | Haiku 5.5 | 3 | 21.7 | 2.3 | 93.1 | 0.35 | 2.43 | 49 |
| P5 cost-aware stopping (lambda=0.01) | Haiku 5.5 | 3 | 23.0 | 1.0 | 95.9 | 0.27 | 1.02 | 4 |
| P5 cost-aware stopping (lambda=0.05) | Haiku 5.5 | 3 | 20.7 | 1.0 | 91.2 | 0.26 | 0.64 | 4 |
| P5 cost-aware stopping (lambda=0.1) | Haiku 5.5 | 3 | 20.0 | 0.7 | 89.9 | 0.26 | 0.64 | 4 |
| P5 cost-aware stopping (lambda=0.25) | Haiku 5.5 | 3 | 19.3 | 0.7 | 88.6 | 0.26 | 0.37 | 4 |
| P5 cost-aware stopping (lambda=0.5) | Haiku 5.5 | 3 | 19.0 | 0.7 | 87.9 | 0.26 | 0.35 | 2 |
| fixed: L0_none | Opus 5.5 | 3 | 18.7 | 0.7 | 87.3 | 6.79 | 0.00 | 0 |
| fixed: L3_+ip | Opus 5.5 | 3 | 23.7 | 2.0 | 97.2 | 11.06 | 3.00 | 100 |
| fixed: L4_+audit | Opus 5.5 | 3 | 23.3 | 2.3 | 96.5 | 14.19 | 4.00 | 100 |
| fixed: only_ip | Opus 5.5 | 3 | 24.0 | 1.3 | 97.9 | 10.12 | 1.00 | 100 |
| P1 escalation [0.2,0.8] | Opus 5.5 | 3 | 22.0 | 0.0 | 94.0 | 7.97 | 0.13 | 2 |
| P1 escalation [0.1,0.9] | Opus 5.5 | 3 | 23.0 | 1.7 | 95.9 | 32.38 | 2.93 | 86 |
| P2 alert-type routing (LOHO) | Opus 5.5 | 3 | 23.7 | 1.7 | 97.2 | 7.17 | 1.00 | 17 |
| P5 cost-aware stopping (lambda=0.0) | Opus 5.5 | 3 | 23.3 | 2.3 | 96.5 | 8.05 | 1.52 | 27 |
| P5 cost-aware stopping (lambda=0.01) | Opus 5.5 | 3 | 24.0 | 1.0 | 97.9 | 6.62 | 0.99 | 2 |
| P5 cost-aware stopping (lambda=0.05) | Opus 5.5 | 3 | 24.0 | 1.0 | 97.9 | 6.62 | 0.99 | 2 |
| P5 cost-aware stopping (lambda=0.1) | Opus 5.5 | 3 | 24.0 | 1.0 | 97.9 | 6.62 | 0.99 | 2 |
| P5 cost-aware stopping (lambda=0.25) | Opus 5.5 | 3 | 24.0 | 1.0 | 97.9 | 6.62 | 0.99 | 2 |
| P5 cost-aware stopping (lambda=0.5) | Opus 5.5 | 3 | 23.3 | 1.0 | 96.6 | 6.67 | 0.99 | 1 |
| P4 cascade Haiku->Opus [0.2,0.8] | Haiku->Opus | 3 | 24.0 | 2.0 | 97.8 | 0.75 | 1.00 | 100 |
| P4 cascade Haiku->Opus [0.1,0.9] | Haiku->Opus | 3 | 24.0 | 1.3 | 97.9 | 2.92 | 1.00 | 100 |
