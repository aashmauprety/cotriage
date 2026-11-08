# Memorization check (Setting C): original vs. renamed prompts

Sample: 50 malicious + 50 benign cases. Agreement = share of cases with the same verdict.

| model | condition | detected orig. / renamed | false alarms orig. / renamed | agreement orig. vs renamed | agreement run 1 vs run 2 |
|---|---|---|---|---|---|
| claude-haiku-5-5 | L0_none | 34 / 35 | 0 / 0 | 99% | 100% |
| claude-haiku-5-5 | L4_+host | 45 / 45 | 5 / 2 | 95% | 95% |
| claude-haiku-5-5 | only_ip | 45 / 44 | 7 / 10 | 92% | 95% |
| claude-opus-5-5 | L0_none | 43 / 43 | 0 / 0 | 100% | - |
| claude-opus-5-5 | L4_+host | 48 / 48 | 0 / 0 | 98% | - |
