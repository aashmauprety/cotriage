# Non-LLM baselines (Setting A, leave-one-host-out)

| baseline | cases | detected | false alarms | balanced acc. |
|---|---|---|---|---|
| B0 escalate every alert | 175 sample | 25/25 | 150/150 | 50.0 |
| B1 IDS priority 1 only | 175 sample | 15/25 | 150/150 | 30.0 |
| B1 IDS priority >= 2 only | 175 sample | 10/25 | 0/150 | 70.0 |
| B2 rarity / burst (unsupervised, T by LOHO) | 175 sample | 22/25 | 21/150 | 87.0 |
| B3 decision tree (supervised) | 175 sample | 18/25 | 2/150 | 85.3 |
| B3 random forest (supervised) | 175 sample | 23/25 | 1/150 | 95.7 |
| B2 rarity, cleartext-password signature only | 175 sample | 4/7 | 21/150 | 71.6 |
| B3 random forest, cleartext-password signature only | 175 sample | 5/7 | 1/150 | 85.4 |
| B0 escalate every alert | all 589 | 25/25 | 564/564 | 50.0 |
| B1 IDS priority 1 only | all 589 | 15/25 | 563/564 | 30.1 |
| B1 IDS priority >= 2 only | all 589 | 10/25 | 1/564 | 69.9 |
| B2 rarity / burst (unsupervised, T by LOHO) | all 589 | 22/25 | 98/564 | 85.3 |
| B3 decision tree (supervised) | all 589 | 24/25 | 16/564 | 96.6 |
| B3 random forest (supervised) | all 589 | 24/25 | 1/564 | 97.9 |
| B2 rarity, cleartext-password signature only | all 589 | 4/7 | 97/563 | 70.0 |
| B3 random forest, cleartext-password signature only | all 589 | 6/7 | 0/563 | 92.9 |

# Per held-out host (all 589 cases): detected/attacks, false alarms/benign, BA

| baseline | cup | insect | onion | spiral |
|---|---|---|---|---|
| B2 rarity / burst | 6/6, 30/185, 91.9 | 5/6, 32/182, 82.9 | 6/6, 18/54, 83.3 | 5/7, 18/143, 79.4 |
| B3 random forest | 6/6, 0/185, 100.0 | 6/6, 1/182, 99.7 | 6/6, 0/54, 100.0 | 6/7, 0/143, 92.9 |
