# Model A results

Command: `python experiments/model_a.py`  |  code at 2479c4c  |  raw numbers: `model_a.json`

Split by sequence number (seed 20261017): 858 train files, 522 test files (30 held-out sequence numbers, 310 encrypted test files).

## All test files (encrypted vs everything else)

| model | precision | recall | F1 | AUC |
|---|---|---|---|---|
| logreg | 1.0 | 0.997 | 0.998 | 0.999 |
| random_forest | 1.0 | 0.997 | 0.998 | 0.998 |

**Caveat on the 0.998:** the model relies heavily on the file-signature (`magic`) feature, which is the top forest feature (importance 0.434). Without it, F1 falls to 0.974 (forest) and the false-positive rate on benign archives rises from 0.0 to 0.458 (see the ablation below). The score therefore largely reflects that NapierOne's encrypted files lack headers; ransomware that preserves headers would not be covered by this result.

Shannon-delta rule (delta > 0.4 bits/byte vs the original), 310 encrypted files with an original: recall 0.723.

## Per file type (encrypted copies vs originals of that type)

| type | enc n | orig n | logreg P/R/F1 | forest P/R/F1 | Shannon-delta recall |
|---|---|---|---|---|---|
| doc | 50 | 30 | 1.0/0.98/0.99 | 1.0/0.98/0.99 | 0.98 |
| docx | 50 | 30 | 1.0/1.0/1.0 | 1.0/1.0/1.0 | 1.0 |
| jpg | 36 | 30 | 1.0/1.0/1.0 | 1.0/1.0/1.0 | 0.25 |
| pdf | 44 | 30 | 1.0/1.0/1.0 | 1.0/1.0/1.0 | 0.114 |
| pptx | 44 | 8 | 1.0/1.0/1.0 | 1.0/1.0/1.0 | 0.75 |
| xls | 43 | 30 | 1.0/1.0/1.0 | 1.0/1.0/1.0 | 0.814 |
| xlsx | 43 | 30 | 1.0/1.0/1.0 | 1.0/1.0/1.0 | 1.0 |

Shannon-delta precision on originals is 1.0 by construction (an unchanged file has delta 0).

## Archives (benign, high entropy): false-positive rate

| rule | FPR | n |
|---|---|---|
| logreg | 0.0 | 24 |
| random_forest | 0.0 | 24 |
| shannon_delta_archive_over_plaintext | 1.0 | 24 |

## Per family recall on the test split

| family | n | logreg | forest |
|---|---|---|---|
| DHARMA | 44 | 1.0 | 1.0 |
| MAZE | 44 | 1.0 | 1.0 |
| NETWALKER | 44 | 1.0 | 1.0 |
| NOTPETYA | 46 | 0.978 | 0.978 |
| PHOBOS | 44 | 1.0 | 1.0 |
| RYUK | 44 | 1.0 | 1.0 |
| SODINOKIBI | 44 | 1.0 | 1.0 |

## Leave-one-family-out (forest recall on the held-out family's test files)

| family | recall | n |
|---|---|---|
| DHARMA | 1.0 | 44 |
| MAZE | 1.0 | 44 |
| NETWALKER | 1.0 | 44 |
| NOTPETYA | 0.978 | 46 |
| PHOBOS | 1.0 | 44 |
| RYUK | 1.0 | 44 |
| SODINOKIBI | 1.0 | 44 |

## Shortcut check: feature ablation (same test files)

| model/features | P | R | F1 | archive FPR | recall by type |
|---|---|---|---|---|---|
| logreg/all | 1.0 | 0.997 | 0.998 | 0.0 | doc:0.98 docx:1.0 jpg:1.0 pdf:1.0 pptx:1.0 xls:1.0 xlsx:1.0 |
| random_forest/all | 1.0 | 0.997 | 0.998 | 0.0 | doc:0.98 docx:1.0 jpg:1.0 pdf:1.0 pptx:1.0 xls:1.0 xlsx:1.0 |
| logreg/no_magic | 0.848 | 0.955 | 0.898 | 1.0 | doc:0.94 docx:1.0 jpg:1.0 pdf:0.955 pptx:1.0 xls:0.791 xlsx:1.0 |
| random_forest/no_magic | 0.965 | 0.984 | 0.974 | 0.458 | doc:0.94 docx:1.0 jpg:0.972 pdf:1.0 pptx:0.977 xls:1.0 xlsx:1.0 |
| logreg/entropy_only | 0.791 | 0.916 | 0.849 | 1.0 | doc:0.94 docx:1.0 jpg:1.0 pdf:0.955 pptx:0.773 xls:0.744 xlsx:1.0 |
| random_forest/entropy_only | 0.952 | 0.958 | 0.955 | 0.625 | doc:0.9 docx:0.98 jpg:0.944 pdf:0.977 pptx:0.977 xls:0.953 xlsx:0.977 |

## Forest feature importance

- magic: 0.434
- head_entropy: 0.227
- max_frac: 0.144
- entropy: 0.077
- chi2: 0.065
- zero_frac: 0.034
- mid_entropy: 0.009
- printable_frac: 0.009
- distinct_frac: 0.001
