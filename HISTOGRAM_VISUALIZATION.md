# Histogram Visualization Feature

## Overview
The histogram visualization provides spatial analysis of bit differences across all constant pairs, helping identify vulnerabilities in the bit difference distribution that could be exploited by fault injection attacks.

## What It Shows

### 1. Hamming Distance Distribution
ASCII bar chart showing how many pairs have each Hamming distance value.

```
Hamming Distance Distribution:

  d= 8 │██████████████████████                             │   4 pairs ( 26.7%)
  d= 9 │██████████████████████████████████████████████████ │   9 pairs ( 60.0%)
  d=10 │█████                                              │   1 pairs (  6.7%)
  d=14 │█████                                              │   1 pairs (  6.7%)
```

**What to look for:**
- **Even distribution**: Most pairs should have similar distances
- **No gaps**: Missing distance values may indicate structure
- **Clustered values**: Good if centered around minimum distance

### 2. Bit Position Heatmap
Visual representation showing which bit positions differ most frequently.

```
Bit Position Difference Frequency (hot spots = frequently different):

  Bit:     0       8       16      24
        ███████▓ ████████ ████████ ████████
  Byte:    0       1       2       3

  Legend:  =0% ░=25% ▒=50% ▓=75% █=100%
```

**Intensity levels:**
- ` ` (space) = 0% - bit never differs
- `░` = ~25% - rarely differs
- `▒` = ~50% - sometimes differs
- `▓` = ~75% - frequently differs
- `█` = 100% - always differs (hotspot)

**What to look for:**
- **Even intensity**: All positions should have similar activity
- **No cold spots**: Bits that never differ are vulnerable
- **No extreme hotspots**: Overly active bits may indicate pattern

### 3. Byte-Level Analysis
Detailed statistics per byte with mini bar charts.

```
  Byte-level difference counts:
    Byte 0: │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░│   46 diffs ( 57.5%)
    Byte 1: │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│   48 diffs ( 60.0%)
    Byte 2: │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│   48 diffs ( 60.0%)
    Byte 3: │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│   48 diffs ( 60.0%)

  ✓ Good: Differences are well-distributed across bytes (4.2% imbalance)
```

**Quality assessment:**
- **< 30% imbalance**: ✓ Good - well distributed
- **≥ 30% imbalance**: ⚠ Warning - uneven distribution

## Usage

### With Generation Mode
```bash
# Generate constants with histogram visualization
python3 secure_constants.py --bits 32 --count 10 --show-histogram

# Combine with auto-discovery
python3 secure_constants.py --bits 16 --count 8 --show-histogram
```

### With Verification Mode
```bash
# Verify existing constants with histogram
python3 secure_constants.py --verify constants.txt --show-histogram

# Combine with bit width specification
python3 secure_constants.py --verify constants.h --bits 32 --show-histogram
```

### With Other Analysis
```bash
# Combine histogram with clustering analysis
python3 secure_constants.py --bits 32 --count 10 --show-histogram --show-clustering

# Full analysis: bounds + histogram + clustering
python3 secure_constants.py --bits 32 --count 10 --show-bounds --show-histogram --show-clustering
```

## Security Analysis

### Good Distribution Example
```
Hamming Distance Distribution:
  d=16 │████████████████████████                           │  12 pairs
  d=17 │██████████████████████████████████████████████████ │  25 pairs
  d=18 │██████████████████████                             │  11 pairs

Bit Position Heatmap:
  ███████ ████████ ████████ ████████  (uniform intensity)

Byte-level:
  ✓ Good: Differences are well-distributed across bytes (2.3% imbalance)
```

**Interpretation:**
- Hamming distances clustered around target value
- Bit positions uniformly active (no cold/hot spots)
- Bytes evenly balanced
- **Security**: Strong against both global and localized faults

### Poor Distribution Example
```
Hamming Distance Distribution:
  d= 8 │██████████████████████████████████████████████████ │  45 pairs
  d=16 │████                                               │   3 pairs

Bit Position Heatmap:
  ████░░░░ ░░░░░░░░ ░░░░░░░░ ░░░░░░░░  (concentrated in byte 0)

Byte-level:
  ⚠ Warning: Byte imbalance detected (68.5%)
  Differences are not evenly distributed across bytes.
```

**Interpretation:**
- Large gap in Hamming distance values
- Bit differences concentrated in byte 0
- Other bytes rarely differ
- **Security**: Vulnerable to byte-targeted fault injection

## Attack Scenarios Detected

### 1. Byte-Localized Vulnerability
```
Byte 0: │████████████████████│  80 diffs (HIGH)
Byte 1: │████░░░░░░░░░░░░░░░░│  20 diffs (LOW)
```
**Risk**: Attacker can target byte 0 with localized voltage glitch

### 2. Bit Position Clustering
```
Bit:  76543210 76543210
      ████░░░░ ░░░░░░░░
```
**Risk**: Upper nibble vulnerable to fault injection

### 3. Uneven Hamming Distance
```
d=4 │██████████████████████████████ │  30 pairs
d=5 │██                             │   2 pairs
d=6-15: (no pairs)
d=16│██████████                     │  10 pairs
```
**Risk**: Large gap indicates structural patterns in constants

## Comparison with Clustering Analysis

| Feature | Histogram | Clustering Analysis |
|---------|-----------|---------------------|
| **Focus** | Global distribution | Per-pair quality |
| **Granularity** | All pairs aggregate | Individual pairs |
| **Visualization** | ASCII charts | Numerical scores |
| **Speed** | Very fast | Moderate |
| **Use case** | Quick overview | Detailed investigation |

**Recommendation**: Use histogram for initial assessment, clustering for deep dive.

## Performance

- **Generation overhead**: Minimal (~1-2% for typical sets)
- **Memory usage**: O(n²) for pair analysis
- **Display time**: Instant for sets up to 1000 constants

## Integration with CI/CD

```bash
#!/bin/bash
# Verify constants with histogram analysis

python3 secure_constants.py --verify src/constants.h --show-histogram > report.txt

# Check for warnings in output
if grep -q "Warning: Byte imbalance" report.txt; then
    echo "ERROR: Constants have poor bit distribution!"
    exit 1
fi

echo "Constants pass histogram analysis"
```

## Example Session

```bash
$ python3 secure_constants.py --bits 16 --count 8 --show-histogram

Generated 8 constants (16-bit)
Minimum Hamming distance: 8

======================================================================
Bit Difference Distribution Analysis:
======================================================================

Hamming Distance Distribution:

  d= 8 │████████████████████                               │   6 pairs
  d= 9 │██████████████████████████████████████████████████ │  12 pairs
  d=10 │████████████████                                   │   4 pairs
  d=11 │████████                                           │   2 pairs
  d=12 │████                                               │   1 pairs
  d=13 │████                                               │   1 pairs
  d=14 │████                                               │   2 pairs

Bit Position Difference Frequency:
  Bit:     0       8
        ████████ ████████
  Byte:    0       1

  Byte-level difference counts:
    Byte 0: │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░│  128 diffs
    Byte 1: │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░│  125 diffs

  ✓ Good: Differences are well-distributed across bytes (2.3% imbalance)
```

## Best Practices

1. **Always review histogram** for new constant sets
2. **Look for imbalance > 30%** as red flag
3. **Check for cold spots** in heatmap (never-differing bits)
4. **Verify even Hamming distribution** around minimum distance
5. **Combine with clustering** for high-security applications
6. **Document** histogram results in security audit trail

## Technical Details

### Calculation Method
1. For each pair (i, j): calculate XOR = constants[i] ^ constants[j]
2. Count differing bits at each position
3. Aggregate by byte and distance
4. Normalize for visualization

### Complexity
- Time: O(n² × w) where n = constants, w = bit width
- Space: O(w + h) where h = unique Hamming distances

### Accuracy
- Exact for all bit widths up to 64
- No approximation or sampling used
- Results are deterministic and reproducible
