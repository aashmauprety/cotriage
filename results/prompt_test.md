# Prompt-wording check (Setting C, Haiku)

2235 cases; original prompt = mean (min-max) over 3 runs; reworded prompt = one run.
Agreement = share of cases with the same verdict as original run 1 (original: runs 2 and 3 vs run 1).

| configuration | BA original | BA reworded | det. orig / reworded | FA orig / reworded | agreement orig. runs | agreement reworded |
|---|---|---|---|---|---|---|
| L0_none | 80.9 (80.8-81.1) | 81.7 | 145.3 / 149 | 0.7 / 1 | 99.7-99.7% | 99.7% |
| L1_history | 82.1 (81.4-82.7) | 81.8 | 151.3 / 150 | 3.3 / 5 | 99.3-99.6% | 99.3% |
| L2_+context | 88.1 (87.8-88.5) | 88.3 | 185.0 / 187 | 49.7 / 60 | 98.2-97.8% | 96.9% |
| L3_+ip | 88.8 (88.5-89.1) | 89.0 | 201.3 / 205 | 159.7 / 185 | 96.1-96.0% | 95.3% |
| L4_+host | 91.9 (91.7-92.2) | 91.7 | 212.3 / 215 | 131.7 / 160 | 97.0-97.1% | 95.9% |
| only_context | 86.4 (85.9-87.1) | 87.3 | 183.0 / 189 | 103.0 / 115 | 96.8-97.1% | 96.4% |
| only_ip | 87.7 (86.8-88.3) | 87.5 | 199.3 / 200 | 187.0 / 204 | 96.0-95.6% | 95.0% |
| only_host | 84.4 (84.2-84.6) | 83.7 | 164.7 / 161 | 23.7 / 23 | 98.8-98.8% | 98.3% |
| P2 routing (lambda=0.05) | 93.0 (91.9-94.2) | 93.1 | 202.3 / 203 | 1.7 / 2 | - | - |
| P2 cost ($ per 1k cases) | 0.19 | 0.20 | | | | |

Unparsed answers in the reworded run (counted as malicious): 1

## Attacks detected per alert type, all tools (original mean / reworded)

| alert type | cases | original | reworded |
|---|---|---|---|
| Suricata: ET INFO Observed DNS Query to .biz TLD | 40 | 40.0 | 40 |
| Web server 400 error code. | 21 | 21.0 | 21 |
| sshd: insecure connection attempt (scan). | 16 | 6.0 | 8 |
| Apache: Attempt to access forbidden file or directory. | 13 | 13.0 | 13 |
| Multiple web server 400 error codes from same source ip. | 12 | 12.0 | 12 |
| Suricata: SURICATA TLS invalid SSLv2 header | 10 | 8.3 | 9 |
| Suricata: ET SCAN Possible Nmap User-Agent Observed | 10 | 10.0 | 10 |
| Suricata: SURICATA SMTP invalid reply | 10 | 5.0 | 5 |
| Web server 500 error code (Internal Error). | 10 | 10.0 | 10 |
| Suricata: SURICATA SMTP no server welcome message | 10 | 6.0 | 6 |
| Suricata: SURICATA TLS invalid record/traffic | 9 | 7.7 | 7 |
| Common web attack. | 8 | 8.0 | 8 |
| Apache: Attempt to access forbidden directory index. | 8 | 8.0 | 8 |
| PAM: Login session closed. | 8 | 8.0 | 8 |
| PAM: Login session opened. | 8 | 8.0 | 8 |
| Successful sudo to ROOT executed. | 8 | 8.0 | 8 |
| User successfully changed UID. | 8 | 8.0 | 8 |
| Suspicious URL access. | 8 | 8.0 | 8 |
| First time user executed sudo. | 6 | 6.0 | 6 |
| Suricata: SURICATA HTTP unable to match response to request | 4 | 3.3 | 4 |
| CMS (WordPress or Joomla) login attempt. | 3 | 3.0 | 3 |
| CMS (WordPress or Joomla) brute force attempt. | 3 | 3.0 | 3 |
| Suricata: SURICATA TLS invalid record type | 2 | 2.0 | 2 |
