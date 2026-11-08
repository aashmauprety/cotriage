# Setting C: balanced accuracy (%) vs. number of labeled training networks

Mean over 20 random draws of the training networks (min-max in parentheses); P2 lambda=0.05.

| method | 1 network | 2 networks | 4 networks | 7 networks |
|---|---|---|---|---|
| Random forest | 74.2 (67.1-79.7) | 83.0 (77.3-87.6) | 91.0 (85.2-96.1) | 96.8 |
| Haiku 5.5 P2 routing | 92.3 (91.4-93.1) | 92.8 (92.1-93.5) | 92.7 (91.8-93.3) | 93.0 |
| Opus 5.5 P2 routing | 97.5 (96.8-98.4) | 97.8 (97.2-98.7) | 97.6 (97.0-98.2) | 97.0 |
| Gemini 3.7 Flash P2 routing | 93.4 (92.3-94.6) | 94.4 (93.6-95.5) | 95.2 (94.0-96.0) | 95.7 |
| Gemini 3.5 Flash-Lite P2 routing | 87.1 (86.3-88.3) | 88.3 (87.2-90.0) | 89.3 (88.5-90.6) | 90.1 |
| Haiku 5.5 no tools (no labels) | 80.9 | 80.9 | 80.9 | 80.9 |
| Haiku 5.5 all tools (no labels) | 91.9 | 91.9 | 91.9 | 91.9 |
| Opus 5.5 no tools (no labels) | 88.4 | 88.4 | 88.4 | 88.4 |
| Opus 5.5 all tools (no labels) | 97.9 | 97.9 | 97.9 | 97.9 |
| Gemini 3.7 Flash no tools (no labels) | 83.2 | 83.2 | 83.2 | 83.2 |
| Gemini 3.7 Flash all tools (no labels) | 96.4 | 96.4 | 96.4 | 96.4 |
| Gemini 3.5 Flash-Lite no tools (no labels) | 79.8 | 79.8 | 79.8 | 79.8 |
| Gemini 3.5 Flash-Lite all tools (no labels) | 93.1 | 93.1 | 93.1 | 93.1 |
