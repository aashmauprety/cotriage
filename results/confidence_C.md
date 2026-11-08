# Setting C: confidence on missed attacks and benign alerts

Confidence that the alert is malicious, averaged per alert over the runs. Missed = attack dismissed in every run.

| model | configuration | runs | missed attacks | median confidence (missed) | IQR (missed) | benign alerts | median confidence (benign) | IQR (benign) |
|---|---|---|---|---|---|---|---|---|
| Haiku 5.5 | L0_none | 3 | 86 | 0.11 | 0.07-0.18 | 2000 | 0.08 | 0.02-0.12 |
| Haiku 5.5 | L4_+host | 3 | 16 | 0.21 | 0.16-0.24 | 2000 | 0.09 | 0.05-0.22 |
| Opus 5.5 | L0_none | 3 | 53 | 0.10 | 0.10-0.12 | 2000 | 0.05 | 0.03-0.06 |
| Opus 5.5 | L4_+host | 3 | 6 | 0.17 | 0.12-0.26 | 2000 | 0.04 | 0.03-0.05 |
