# Bootstrap confidence intervals of the balanced accuracy

## Setting A, all 589 cases (25 attacks, 564 benign; 5000 stratified resamples)

| method | BA | 95% CI |
|---|---|---|
| Random forest | 97.9 | 93.8-100.0 |
| Haiku S0 | 68.7 | 60.7-77.3 |
| Haiku tau3 | 97.0 | 92.5-99.8 |
| Haiku S4 | 99.7 | 99.4-100.0 |
| Haiku P2 | 95.9 | 90.7-99.9 |
| Opus S0 | 87.3 | 78.7-94.7 |
| Opus tau3 | 97.9 | 93.8-100.0 |
| Opus P2 | 97.2 | 92.6-100.0 |

| comparison | difference (BA points) | 95% CI | share of resamples > 0 |
|---|---|---|---|
| Haiku tau3 minus Opus S0 | +9.7 | +2.5 to +17.7 | 99.7% |
| Haiku S4 minus Random forest | +1.8 | -0.4 to +5.9 | 67.3% |
| Haiku S4 minus Opus S0 | +12.5 | +4.9 to +20.8 | 100.0% |
| Haiku P2 minus Haiku S0 | +27.2 | +18.6 to +35.3 | 100.0% |
| Opus P2 minus Opus S0 | +10.0 | +3.3 to +17.3 | 99.9% |
| Haiku S4 minus Haiku P2 | +3.8 | -0.1 to +8.8 | 96.3% |

## Setting C, eight scenarios (235 attacks, 2000 benign; 5000 stratified resamples)

| method | BA | 95% CI |
|---|---|---|
| Haiku S0 | 80.9 | 77.9-83.9 |
| Haiku S4 | 91.9 | 90.0-93.5 |
| Haiku tau3 | 87.7 | 85.5-89.9 |
| Haiku P2 | 93.0 | 91.0-94.9 |
| Opus S0 | 88.4 | 85.7-91.1 |
| Opus S4 | 97.9 | 96.7-99.0 |
| Opus tau3 | 95.6 | 93.9-97.1 |
| Opus P2 | 97.0 | 95.5-98.4 |
| Gemini S0 | 83.2 | 80.2-86.1 |
| Gemini S4 | 96.4 | 94.8-97.7 |
| Gemini tau3 | 94.2 | 92.4-95.9 |
| Gemini P2 | 95.7 | 93.9-97.3 |
| Lite S0 | 79.8 | 76.7-83.0 |
| Lite S4 | 93.1 | 90.9-95.1 |
| Lite tau3 | 85.7 | 82.9-88.5 |
| Lite P2 | 90.1 | 87.6-92.5 |
| Wazuh level | 69.6 | 66.3-72.8 |
| Rarity / burst | 71.3 | 68.0-74.5 |
| Random forest | 96.8 | 95.2-98.2 |

| comparison | difference (BA points) | 95% CI | share of resamples > 0 |
|---|---|---|---|
| Haiku P2 minus Haiku S4 | +1.1 | -0.4 to +2.6 | 92.4% |
| Haiku P2 minus Haiku S0 | +12.1 | +9.6 to +14.7 | 100.0% |
| Opus P2 minus Opus S0 | +8.6 | +6.3 to +11.0 | 100.0% |
| Opus P2 minus Random forest | +0.2 | -1.8 to +2.2 | 58.2% |
| Opus S4 minus Random forest | +1.1 | -0.5 to +2.9 | 89.4% |
| Haiku S4 minus Opus S0 | +3.4 | +0.6 to +6.3 | 99.2% |
| Random forest minus Haiku P2 | +3.8 | +1.4 to +6.3 | 99.9% |
| Gemini P2 minus Gemini S0 | +12.5 | +9.8 to +15.2 | 100.0% |
| Gemini P2 minus Gemini S4 | -0.7 | -2.0 to +0.6 | 14.0% |
| Gemini P2 minus Random forest | -1.2 | -3.2 to +0.9 | 13.5% |
| Gemini S4 minus Opus S0 | +7.9 | +5.2 to +10.7 | 100.0% |
| Lite S4 minus Lite S0 | +13.3 | +10.5 to +16.2 | 100.0% |
| Lite P2 minus Lite S0 | +10.3 | +7.8 to +12.8 | 100.0% |
| Lite S4 minus Opus S0 | +4.6 | +1.6 to +7.6 | 99.9% |
| Lite S4 minus Haiku S4 | +1.2 | -0.1 to +2.5 | 96.4% |

