# Setting C: routing on seen vs unseen signatures and attack steps

Leave-one-scenario-out throughout; lambda=0.05; mean over runs. 'sig' = paper P2 (unseen signature -> IP activity),
'backoff' = signature -> log-source family -> all training cases (class-balanced errors at fallback levels).

Attack steps: cracking: 1 signatures; escalation: 5 signatures; exfiltration: 1 signatures; scan: 7 signatures; web: 9 signatures

| model | training excludes | policy | det | FA | BA | $ per 1k | det by step (scan/web/cracking/escalation/exfil) |
|---|---|---|---|---|---|---|---|
| Haiku 5.5 | - | fixed L0_none | 145.3 | 0.7 | 80.9 | 0.19 | 10.0/74.0/0.0/21.3/40.0 |
| Haiku 5.5 | - | fixed L4_+host | 212.3 | 131.7 | 91.9 | 0.32 | 45.0/86.0/3.3/38.0/40.0 |
| Haiku 5.5 | - | fixed only_ip | 199.3 | 187.0 | 87.7 | 0.27 | 49.3/85.7/2.3/22.0/40.0 |
| Haiku 5.5 | test network | sig | 202.3 | 1.7 | 93.0 | 0.19 | 37.0/84.7/2.7/38.0/40.0 |
| Haiku 5.5 | + test signature | sig | 199.3 | 187.0 | 87.7 | 0.27 | 49.3/85.7/2.3/22.0/40.0 |
| Haiku 5.5 | + test signature | backoff | 204.0 | 50.7 | 92.1 | 0.23 | 42.7/85.7/2.3/33.3/40.0 |
| Haiku 5.5 | + test signature | all | 212.3 | 131.7 | 91.9 | 0.32 | 45.0/86.0/3.3/38.0/40.0 |
| Haiku 5.5 | + test attack step | sig | 199.3 | 187.0 | 87.7 | 0.27 | 49.3/85.7/2.3/22.0/40.0 |
| Haiku 5.5 | + test attack step | backoff | 167.3 | 46.3 | 84.4 | 0.22 | 13.7/86.0/2.3/25.3/40.0 |
| Haiku 5.5 | + test attack step | all | 212.3 | 131.7 | 91.9 | 0.32 | 45.0/86.0/3.3/38.0/40.0 |
| Opus 5.5 | - | fixed L0_none | 180.7 | 0.0 | 88.4 | 5.17 | 26.0/84.7/0.0/30.0/40.0 |
| Opus 5.5 | - | fixed L4_+host | 226.3 | 8.7 | 97.9 | 7.76 | 58.3/86.0/4.0/38.0/40.0 |
| Opus 5.5 | - | fixed only_ip | 217.3 | 26.7 | 95.6 | 6.02 | 57.3/86.0/4.0/30.0/40.0 |
| Opus 5.5 | test network | sig | 221.7 | 5.7 | 97.0 | 5.23 | 53.7/86.0/4.0/38.0/40.0 |
| Opus 5.5 | + test signature | sig | 217.3 | 26.7 | 95.6 | 6.02 | 57.3/86.0/4.0/30.0/40.0 |
| Opus 5.5 | + test signature | backoff | 218.0 | 23.3 | 95.8 | 6.04 | 58.7/85.3/4.0/30.0/40.0 |
| Opus 5.5 | + test signature | all | 226.3 | 8.7 | 97.9 | 7.76 | 58.3/86.0/4.0/38.0/40.0 |
| Opus 5.5 | + test attack step | sig | 217.3 | 26.7 | 95.6 | 6.02 | 57.3/86.0/4.0/30.0/40.0 |
| Opus 5.5 | + test attack step | backoff | 216.0 | 26.3 | 95.3 | 6.05 | 56.0/86.0/4.0/30.0/40.0 |
| Opus 5.5 | + test attack step | all | 226.3 | 8.7 | 97.9 | 7.76 | 58.3/86.0/4.0/38.0/40.0 |
| Gemini 3.7 Flash | - | fixed L0_none | 156.0 | 0.0 | 83.2 | 1.08 | 11.3/77.3/0.0/27.3/40.0 |
| Gemini 3.7 Flash | - | fixed L4_+host | 220.7 | 23.7 | 96.4 | 1.50 | 52.7/86.0/4.0/38.0/40.0 |
| Gemini 3.7 Flash | - | fixed only_ip | 212.3 | 38.7 | 94.2 | 1.24 | 55.3/86.0/4.0/27.0/40.0 |
| Gemini 3.7 Flash | test network | sig | 214.7 | 0.7 | 95.7 | 1.14 | 51.0/83.7/3.0/37.0/40.0 |
| Gemini 3.7 Flash | + test signature | sig | 212.3 | 38.7 | 94.2 | 1.24 | 55.3/86.0/4.0/27.0/40.0 |
| Gemini 3.7 Flash | + test signature | backoff | 214.0 | 37.3 | 94.6 | 1.23 | 52.3/82.0/4.0/35.7/40.0 |
| Gemini 3.7 Flash | + test signature | all | 220.7 | 23.7 | 96.4 | 1.50 | 52.7/86.0/4.0/38.0/40.0 |
| Gemini 3.7 Flash | + test attack step | sig | 212.3 | 38.7 | 94.2 | 1.24 | 55.3/86.0/4.0/27.0/40.0 |
| Gemini 3.7 Flash | + test attack step | backoff | 191.7 | 28.0 | 90.1 | 1.24 | 33.7/86.0/4.0/28.0/40.0 |
| Gemini 3.7 Flash | + test attack step | all | 220.7 | 23.7 | 96.4 | 1.50 | 52.7/86.0/4.0/38.0/40.0 |
| Gemini 3.5 Flash-Lite | - | fixed L0_none | 140.3 | 3.0 | 79.8 | 0.31 | 10.0/75.3/0.0/15.0/40.0 |
| Gemini 3.5 Flash-Lite | - | fixed L4_+host | 204.3 | 16.0 | 93.1 | 0.46 | 37.3/86.0/3.0/38.0/40.0 |
| Gemini 3.5 Flash-Lite | - | fixed only_ip | 173.3 | 47.0 | 85.7 | 0.35 | 33.3/86.0/2.0/12.0/40.0 |
| Gemini 3.5 Flash-Lite | test network | sig | 188.7 | 3.7 | 90.1 | 0.32 | 25.7/82.7/3.0/37.3/40.0 |
| Gemini 3.5 Flash-Lite | + test signature | sig | 173.3 | 47.0 | 85.7 | 0.35 | 33.3/86.0/2.0/12.0/40.0 |
| Gemini 3.5 Flash-Lite | + test signature | backoff | 199.3 | 8.0 | 92.2 | 0.40 | 34.3/84.0/3.0/38.0/40.0 |
| Gemini 3.5 Flash-Lite | + test signature | all | 204.3 | 16.0 | 93.1 | 0.46 | 37.3/86.0/3.0/38.0/40.0 |
| Gemini 3.5 Flash-Lite | + test attack step | sig | 173.3 | 47.0 | 85.7 | 0.35 | 33.3/86.0/2.0/12.0/40.0 |
| Gemini 3.5 Flash-Lite | + test attack step | backoff | 161.0 | 7.3 | 84.1 | 0.39 | 14.0/86.0/3.0/18.0/40.0 |
| Gemini 3.5 Flash-Lite | + test attack step | all | 204.3 | 16.0 | 93.1 | 0.46 | 37.3/86.0/3.0/38.0/40.0 |

Attacks per step: scan 67, web 86, cracking 4, escalation 38, exfiltration 40

## Does the best tool set of a signature differ between networks?

Hindsight = tool set chosen per signature and network on the test cases themselves (in-sample upper bound).

| model | signatures in >= 2 networks | best set differs (mean over runs) | BA hindsight | BA P2 | which (run 1) |
|---|---|---|---|---|---|
| Haiku 5.5 | 23 | 17.7 | 96.0 | 93.0 | Apache: Attempt to access forbidden directory index., Apache: Attempt to access forbidden file or directory., CMS (WordPress or Joomla) login attempt., Common web attack., First time user executed sudo., Multiple web server 400 error codes from same source ip., PAM: Login session opened., Successful sudo to ROOT executed., Suricata: ET SCAN Possible Nmap User-Agent Observed, Suricata: SURICATA HTTP unable to match response to request, Suricata: SURICATA SMTP invalid reply, Suricata: SURICATA SMTP no server welcome message, Suricata: SURICATA TLS invalid record type, Suricata: SURICATA TLS invalid record/traffic, Suspicious URL access., User successfully changed UID., Web server 400 error code., Web server 500 error code (Internal Error)., sshd: insecure connection attempt (scan). |
| Opus 5.5 | 23 | 14.0 | 98.9 | 97.0 | Apache: Attempt to access forbidden directory index., Apache: Attempt to access forbidden file or directory., CMS (WordPress or Joomla) brute force attempt., Common web attack., First time user executed sudo., Multiple web server 400 error codes from same source ip., PAM: Login session opened., Successful sudo to ROOT executed., Suricata: ET SCAN Possible Nmap User-Agent Observed, Suricata: SURICATA HTTP unable to match response to request, Suricata: SURICATA SMTP invalid reply, Suricata: SURICATA TLS invalid record/traffic, Suspicious URL access., User successfully changed UID., Web server 500 error code (Internal Error). |
| Gemini 3.7 Flash | 23 | 21.3 | 98.7 | 95.7 | Apache: Attempt to access forbidden directory index., Apache: Attempt to access forbidden file or directory., CMS (WordPress or Joomla) brute force attempt., CMS (WordPress or Joomla) login attempt., Common web attack., First time user executed sudo., Multiple web server 400 error codes from same source ip., PAM: Login session closed., PAM: Login session opened., Successful sudo to ROOT executed., Suricata: ET SCAN Possible Nmap User-Agent Observed, Suricata: SURICATA HTTP unable to match response to request, Suricata: SURICATA SMTP invalid reply, Suricata: SURICATA SMTP no server welcome message, Suricata: SURICATA TLS invalid SSLv2 header, Suricata: SURICATA TLS invalid record/traffic, Suspicious URL access., User successfully changed UID., Web server 400 error code., Web server 500 error code (Internal Error)., sshd: insecure connection attempt (scan). |
| Gemini 3.5 Flash-Lite | 23 | 14.3 | 93.8 | 90.1 | Apache: Attempt to access forbidden directory index., Apache: Attempt to access forbidden file or directory., CMS (WordPress or Joomla) login attempt., First time user executed sudo., Multiple web server 400 error codes from same source ip., PAM: Login session opened., Successful sudo to ROOT executed., Suricata: SURICATA HTTP unable to match response to request, Suricata: SURICATA SMTP invalid reply, Suricata: SURICATA SMTP no server welcome message, Suricata: SURICATA TLS invalid SSLv2 header, Suricata: SURICATA TLS invalid record/traffic, User successfully changed UID., Web server 400 error code., sshd: insecure connection attempt (scan). |
