# Paired bootstrap: routing vs. global routing and learned stopping (Setting C, lambda=0.05)

## Haiku 5.5 (235 attacks, 2000 benign; 5000 stratified resamples)

| method | BA | 95% CI |
|---|---|---|
| P2 routing | 93.0 | 90.8-94.9 |
| global routing | 80.9 | 77.9-83.9 |
| learned stopping | 81.6 | 78.5-84.6 |

| comparison | difference (BA points) | 95% CI | share of resamples > 0 |
|---|---|---|---|
| P2 routing minus global routing | +12.1 | +9.6 to +14.7 | 100.0% |
| P2 routing minus learned stopping | +11.4 | +9.0 to +13.9 | 100.0% |

## Gemini 3.5 Flash-Lite (235 attacks, 2000 benign; 5000 stratified resamples)

| method | BA | 95% CI |
|---|---|---|
| P2 routing | 90.1 | 87.6-92.5 |
| global routing | 84.1 | 81.1-87.0 |
| learned stopping | 80.0 | 76.8-83.0 |

| comparison | difference (BA points) | 95% CI | share of resamples > 0 |
|---|---|---|---|
| P2 routing minus global routing | +6.0 | +4.0 to +8.1 | 100.0% |
| P2 routing minus learned stopping | +10.1 | +7.7 to +12.6 | 100.0% |

## Gemini 3.7 Flash (235 attacks, 2000 benign; 5000 stratified resamples)

| method | BA | 95% CI |
|---|---|---|
| P2 routing | 95.7 | 93.8-97.2 |
| global routing | 90.0 | 87.5-92.2 |
| learned stopping | 87.3 | 84.6-90.0 |

| comparison | difference (BA points) | 95% CI | share of resamples > 0 |
|---|---|---|---|
| P2 routing minus global routing | +5.7 | +3.5 to +8.0 | 100.0% |
| P2 routing minus learned stopping | +8.3 | +5.6 to +11.1 | 100.0% |

## Opus 5.5 (235 attacks, 2000 benign; 5000 stratified resamples)

| method | BA | 95% CI |
|---|---|---|
| P2 routing | 97.0 | 95.5-98.3 |
| global routing | 88.4 | 85.7-91.0 |
| learned stopping | 88.6 | 85.9-91.1 |

| comparison | difference (BA points) | 95% CI | share of resamples > 0 |
|---|---|---|---|
| P2 routing minus global routing | +8.6 | +6.3 to +11.0 | 100.0% |
| P2 routing minus learned stopping | +8.4 | +6.1 to +10.8 | 100.0% |

