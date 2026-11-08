# Tokens per alert (price-independent cost)

Mean over cases and runs. Output tokens include reasoning tokens. P2 = learned routing, lambda=0.05.

## Setting A

| model | configuration | input tokens | output tokens |
|---|---|---|---|
| Haiku 5.5 | L0_none | 612 | 379 |
| Haiku 5.5 | only_suricata | 733 | 392 |
| Haiku 5.5 | only_ip | 1763 | 384 |
| Haiku 5.5 | only_audit | 1397 | 436 |
| Haiku 5.5 | L4_+audit | 2830 | 364 |
| Haiku 5.5 | P2 | 793 | 380 |
| Opus 5.5 | L0_none | 612 | 217 |
| Opus 5.5 | only_suricata | 733 | 182 |
| Opus 5.5 | only_ip | 1763 | 153 |
| Opus 5.5 | only_audit | 1397 | 153 |
| Opus 5.5 | L4_+audit | 2830 | 143 |
| Opus 5.5 | P2 | 741 | 182 |

## Setting C

| model | configuration | input tokens | output tokens |
|---|---|---|---|
| Haiku 5.5 | L0_none | 554 | 261 |
| Haiku 5.5 | only_context | 705 | 407 |
| Haiku 5.5 | only_ip | 688 | 397 |
| Haiku 5.5 | only_host | 691 | 352 |
| Haiku 5.5 | L4_+host | 1103 | 428 |
| Haiku 5.5 | P2 | 579 | 267 |
| Opus 5.5 | L0_none | 554 | 148 |
| Opus 5.5 | only_ip | 688 | 163 |
| Opus 5.5 | L4_+host | 1103 | 167 |
| Opus 5.5 | P2 | 593 | 143 |
| Gemini 3.7 Flash | L0_none | 444 | 199 |
| Gemini 3.7 Flash | only_context | 572 | 202 |
| Gemini 3.7 Flash | only_ip | 565 | 218 |
| Gemini 3.7 Flash | only_host | 562 | 202 |
| Gemini 3.7 Flash | L4_+host | 913 | 217 |
| Gemini 3.7 Flash | P2 | 522 | 199 |
| Gemini 3.5 Flash-Lite | L0_none | 444 | 72 |
| Gemini 3.5 Flash-Lite | only_context | 572 | 73 |
| Gemini 3.5 Flash-Lite | only_ip | 565 | 73 |
| Gemini 3.5 Flash-Lite | only_host | 562 | 72 |
| Gemini 3.5 Flash-Lite | L4_+host | 913 | 74 |
| Gemini 3.5 Flash-Lite | P2 | 476 | 72 |

## Cost relative to no tools for other output/input price ratios

Same decisions (P2 tool sets chosen at our prices); only the price ratio changes.

| setting | model | config | ratio 1 | ratio 3 | ratio 5 | ratio 8 |
|---|---|---|---|---|---|---|
| A | Haiku 5.5 | P2 | 1.18 | 1.11 | 1.08 | 1.05 |
| A | Haiku 5.5 | L4_+audit | 3.22 | 2.24 | 1.86 | 1.58 |
| A | Opus 5.5 | P2 | 1.11 | 1.02 | 0.97 | 0.94 |
| A | Opus 5.5 | L4_+audit | 3.59 | 2.58 | 2.09 | 1.69 |
| C | Haiku 5.5 | P2 | 1.04 | 1.03 | 1.03 | 1.03 |
| C | Haiku 5.5 | L4_+host | 1.88 | 1.78 | 1.74 | 1.71 |
| C | Opus 5.5 | P2 | 1.05 | 1.02 | 1.01 | 1.00 |
| C | Opus 5.5 | L4_+host | 1.81 | 1.61 | 1.50 | 1.41 |
| C | Gemini 3.7 Flash | P2 | 1.12 | 1.08 | 1.05 | 1.04 |
| C | Gemini 3.7 Flash | L4_+host | 1.76 | 1.50 | 1.39 | 1.30 |
| C | Gemini 3.5 Flash-Lite | P2 | 1.06 | 1.05 | 1.04 | 1.03 |
| C | Gemini 3.5 Flash-Lite | L4_+host | 1.91 | 1.72 | 1.60 | 1.48 |
