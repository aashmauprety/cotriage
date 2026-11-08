# Prompt-wording check (Setting C, claude-opus-5-5)

2235 cases; original prompt = mean (min-max) over 3 runs; reworded prompt = one run (INCOMPLETE).
Agreement = share of cases with the same verdict as original run 1 (original: runs 2 and 3 vs run 1).

| configuration | BA original | BA reworded | det. orig / reworded | FA orig / reworded | agreement orig. runs | agreement reworded |
|---|---|---|---|---|---|---|
| L0_none | 88.4 (88.3-88.7) | 86.8 | 180.7 / 173 | 0.0 / 0 | 99.9-99.9% | 99.6% |
| L4_+host | 97.9 (97.6-98.3) | 97.8 | 226.3 / 227 | 8.7 / 20 | 99.4-99.4% | 99.1% |

Unparsed answers in the reworded run (counted as malicious): 2

## Attacks detected per alert type, all tools (original mean / reworded)

| alert type | cases | original | reworded |
|---|---|---|---|
| Suricata: ET INFO Observed DNS Query to .biz TLD | 40 | 40.0 | 40 |
| Web server 400 error code. | 21 | 21.0 | 21 |
| sshd: insecure connection attempt (scan). | 16 | 13.3 | 12 |
| Apache: Attempt to access forbidden file or directory. | 13 | 13.0 | 13 |
| Multiple web server 400 error codes from same source ip. | 12 | 12.0 | 12 |
| Suricata: SURICATA TLS invalid SSLv2 header | 10 | 10.0 | 10 |
| Web server 500 error code (Internal Error). | 10 | 10.0 | 10 |
| Suricata: ET SCAN Possible Nmap User-Agent Observed | 10 | 10.0 | 10 |
| Suricata: SURICATA SMTP invalid reply | 10 | 8.3 | 8 |
| Suricata: SURICATA SMTP no server welcome message | 10 | 7.7 | 9 |
| Suricata: SURICATA TLS invalid record/traffic | 9 | 7.0 | 8 |
| PAM: Login session closed. | 8 | 8.0 | 8 |
| User successfully changed UID. | 8 | 8.0 | 8 |
| PAM: Login session opened. | 8 | 8.0 | 8 |
| Suspicious URL access. | 8 | 8.0 | 8 |
| Successful sudo to ROOT executed. | 8 | 8.0 | 8 |
| Apache: Attempt to access forbidden directory index. | 8 | 8.0 | 8 |
| Common web attack. | 8 | 8.0 | 8 |
| First time user executed sudo. | 6 | 6.0 | 6 |
| Suricata: SURICATA HTTP unable to match response to request | 4 | 4.0 | 4 |
| CMS (WordPress or Joomla) login attempt. | 3 | 3.0 | 3 |
| CMS (WordPress or Joomla) brute force attempt. | 3 | 3.0 | 3 |
| Suricata: SURICATA TLS invalid record type | 2 | 2.0 | 2 |
