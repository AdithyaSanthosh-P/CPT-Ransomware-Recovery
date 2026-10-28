# Model B on Berrueta I/O traces (all)

Command: `python experiments/berrueta_model_b.py --data experiments/data/berrueta/unz/textFiles --label all`  |  Model B logistic regression, trained on our simulator dev seeds only

Recall only (every run is an attack; no benign runs exist in this dataset). Policy PB: Model B alone, count quorum 1, live thresholds. Entropy and Model A are absent (no file contents). Detection time and files are measured from the first close-after-write in the capture.

Runs: 189 IOops files, 166 with activity (>= 20 write-closes), 23 without.

**Detected: 145/166**

Median time to trigger 18.42 s; median files first 12; median % of encrypted files before trigger 0.3.

| family | runs | detected | median s | median files first | median % first |
|---|---|---|---|---|---|
| aleta | 1 | 1 | 0.8 | 4 | 0.1 |
| bart | 2 | 0 | - | - | - |
| bitpaymer | 2 | 2 | 6.28 | 8.5 | 0.05 |
| cerber | 35 | 35 | 19.88 | 11 | 0.4 |
| crypmic | 2 | 0 | - | - | - |
| cryptfile2 | 2 | 1 | 1284.52 | 3461 | 67.3 |
| cryptofortress | 2 | 2 | 7.65 | 9.0 | 0.15000000000000002 |
| cryptomix | 8 | 4 | 992.3199999999999 | 3025.5 | 59.650000000000006 |
| cryptoshield | 3 | 0 | - | - | - |
| crysis | 20 | 20 | 22.235 | 117.0 | 0.8500000000000001 |
| cryxox | 2 | 2 | 5.9399999999999995 | 14.5 | 0.15000000000000002 |
| ctblocker | 2 | 2 | 20.66 | 29.0 | 59.95 |
| dharma | 3 | 3 | 2.37 | 16 | 0.2 |
| diablo6 | 2 | 2 | 22.705 | 8.0 | 0.2 |
| dmalocker | 1 | 0 | - | - | - |
| eris | 2 | 2 | 0.52 | 5.0 | 0.1 |
| gandcrab | 6 | 6 | 2.76 | 17.0 | 0.1 |
| globeimposter | 2 | 2 | 9.5 | 8.5 | 0.2 |
| jaff | 4 | 4 | 0.395 | 7.0 | 0.1 |
| locky | 15 | 15 | 14.24 | 8 | 0.2 |
| maktub | 10 | 10 | 120.405 | 1804.0 | 77.9 |
| maze | 1 | 1 | 464.44 | 2432 | 45.5 |
| mole | 1 | 1 | 307.62 | 617 | 12.0 |
| mrcr | 1 | 1 | 3214.98 | 10 | 0.2 |
| odin | 2 | 2 | 158.42499999999998 | 9.5 | 0.7999999999999999 |
| phobos | 1 | 1 | 53.48 | 26 | 0.4 |
| ransomx | 1 | 1 | 6.57 | 10 | 0.2 |
| razi | 1 | 1 | 20.08 | 11 | 0.2 |
| revenge | 1 | 0 | - | - | - |
| ryuk | 1 | 0 | - | - | - |
| sage | 8 | 8 | 34.305 | 12.0 | 0.1 |
| scarab | 1 | 1 | 3.5 | 6 | 0.1 |
| shade | 1 | 1 | 101.27 | 15 | 0.7 |
| shaofao | 1 | 1 | 226.72 | 716 | 10.9 |
| sodinokibi | 3 | 3 | 12.27 | 35 | 0.7 |
| spora | 2 | 0 | - | - | - |
| stop | 3 | 3 | 0.95 | 8 | 0.2 |
| teslacrypt | 2 | 2 | 35.72 | 8.5 | 0.5 |
| virlock | 5 | 2 | 1.64 | 8.0 | 0.3 |
| wannacry | 3 | 3 | 2.53 | 8 | 0.2 |
| zeus | 1 | 0 | - | - | - |

## Missed runs (max sub-scores show whether the signal was ever high)

| run | scenario | write-closes | files | max rate | max ext | max spread | max Model B |
|---|---|---|---|---|---|---|---|
| CrypMIC_30092016 | NATscenario | 3484 | 3484 | 1.0 | 0.0 | 0.6 | 0.352 |
| CryptoMix_24012017 | NATscenario | 3175 | 3134 | 1.0 | 0.0 | 0.6 | 0.352 |
| CryptoMix_28112016 | NATscenario | 1228 | 1192 | 1.0 | 0.0 | 0.6 | 0.352 |
| CryptoShield_28022017 | NATscenario | 1176 | 1108 | 1.0 | 0.0 | 0.7 | 0.352 |
| Ryuk_16042019 | NATscenario | 5048 | 5048 | 1.0 | 0.0 | 1.0 | 0.352 |
| Spora_17052017 | NATscenario | 4646 | 4645 | 1.0 | 0.0 | 1.0 | 0.352 |
| Virlock_16022017 | NATscenario | 1840 | 1840 | 0.24 | 0.0 | 0.2 | 0.33 |
| Virlock_17072016 | NATscenario | 3087 | 3087 | 0.64 | 0.0 | 0.4 | 0.342 |
| bart_01092016 | NATscenario | 5133 | 5132 | 1.0 | 0.0 | 1.0 | 0.352 |
| CrypMIC_30092016 | originalScenario | 761 | 760 | 1.0 | 0.0 | 0.0 | 0.352 |
| CryptFile2_10112016 | originalScenario | 762 | 760 | 1.0 | 0.0 | 0.0 | 0.352 |
| CryptoMix_12122016 | originalScenario | 1515 | 1514 | 1.0 | 0.0 | 0.2 | 0.352 |
| CryptoMix_28112016 | originalScenario | 1515 | 1514 | 1.0 | 0.0 | 0.2 | 0.352 |
| CryptoShield_28022017 | originalScenario | 5053 | 5017 | 1.0 | 0.0 | 0.3 | 0.352 |
| CryptoShield_31012017 | originalScenario | 1520 | 1516 | 1.0 | 0.0 | 0.3 | 0.352 |
| DMALocker_01022016 | originalScenario | 5033 | 5033 | 1.0 | 0.0 | 1.0 | 0.352 |
| Spora_17052017 | originalScenario | 4636 | 4635 | 1.0 | 0.0 | 1.0 | 0.352 |
| Virlock_17072016 | originalScenario | 565 | 565 | 0.04 | 0.0 | 0.0 | 0.325 |
| Zeus_31102017 | originalScenario | 3385 | 3385 | 1.0 | 0.0 | 1.0 | 0.352 |
| bart_01092016 | originalScenario | 757 | 756 | 1.0 | 0.0 | 0.0 | 0.352 |
| revenge_15032018 | originalScenario | 1699 | 1698 | 0.68 | 0.0 | 0.0 | 0.343 |
