# Prompt-wording check (Setting C, gemini-3.7-flash)

2235 cases; original prompt = mean (min-max) over 3 runs; reworded prompt = one run.
Agreement = share of cases with the same verdict as original run 1 (original: runs 2 and 3 vs run 1).

| configuration | BA original | BA reworded | det. orig / reworded | FA orig / reworded | agreement orig. runs | agreement reworded |
|---|---|---|---|---|---|---|
| L0_none | 83.2 (83.0-83.4) | 83.0 | 156.0 / 155 | 0.0 / 0 | 99.6-99.6% | 99.6% |
| L1_history | 85.6 (85.3-85.9) | 84.2 | 167.3 / 161 | 2.0 / 3 | 99.8-99.6% | 99.6% |
| L2_+context | 91.6 (91.4-91.8) | 90.7 | 196.0 / 192 | 5.3 / 7 | 99.7-99.8% | 99.6% |
| L3_+ip | 94.6 (93.8-95.3) | 94.8 | 213.0 / 214 | 28.0 / 28 | 99.2-99.2% | 99.3% |
| L4_+host | 96.4 (96.2-96.6) | 95.9 | 220.7 / 219 | 23.7 / 28 | 99.6-99.5% | 99.4% |
| only_context | 88.7 (88.3-89.0) | 88.9 | 183.0 / 184 | 8.0 / 9 | 99.6-99.7% | 99.6% |
| only_ip | 94.2 (94.1-94.3) | 93.8 | 212.3 / 210 | 38.7 / 37 | 99.6-99.5% | 99.5% |
| only_host | 88.1 (87.8-88.5) | 86.5 | 179.3 / 172 | 2.3 / 3 | 99.6-99.3% | 99.2% |
| P2 routing (lambda=0.05) | 95.7 (95.3-95.9) | 94.9 | 214.7 / 211 | 0.7 / 0 | - | - |
| P2 cost ($ per 1k cases) | 1.14 | 1.11 | | | | |

Unparsed answers in the reworded run (counted as malicious): 0

## Attacks detected per alert type, all tools (original mean / reworded)

| alert type | cases | original | reworded |
|---|---|---|---|
| Suricata: ET INFO Observed DNS Query to .biz TLD | 40 | 40.0 | 40 |
| Web server 400 error code. | 21 | 21.0 | 21 |
| sshd: insecure connection attempt (scan). | 16 | 10.7 | 10 |
| Apache: Attempt to access forbidden file or directory. | 13 | 13.0 | 13 |
| Multiple web server 400 error codes from same source ip. | 12 | 12.0 | 12 |
| Suricata: ET SCAN Possible Nmap User-Agent Observed | 10 | 10.0 | 10 |
| Suricata: SURICATA SMTP no server welcome message | 10 | 5.3 | 6 |
| Suricata: SURICATA SMTP invalid reply | 10 | 6.0 | 6 |
| Web server 500 error code (Internal Error). | 10 | 10.0 | 10 |
| Suricata: SURICATA TLS invalid SSLv2 header | 10 | 10.0 | 10 |
| Suricata: SURICATA TLS invalid record/traffic | 9 | 8.7 | 7 |
| Common web attack. | 8 | 8.0 | 8 |
| Apache: Attempt to access forbidden directory index. | 8 | 8.0 | 8 |
| User successfully changed UID. | 8 | 8.0 | 8 |
| PAM: Login session closed. | 8 | 8.0 | 8 |
| PAM: Login session opened. | 8 | 8.0 | 8 |
| Suspicious URL access. | 8 | 8.0 | 8 |
| Successful sudo to ROOT executed. | 8 | 8.0 | 8 |
| First time user executed sudo. | 6 | 6.0 | 6 |
| Suricata: SURICATA HTTP unable to match response to request | 4 | 4.0 | 4 |
| CMS (WordPress or Joomla) login attempt. | 3 | 3.0 | 3 |
| CMS (WordPress or Joomla) brute force attempt. | 3 | 3.0 | 3 |
| Suricata: SURICATA TLS invalid record type | 2 | 2.0 | 2 |
