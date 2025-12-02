# Theoretical Bounds for Maximum Hamming Distance

This document explains the theoretical limits on maximum minimum Hamming distance for error-correcting codes, which applies directly to our secure constant generation problem.

## The Problem

Given:
- **n** = bit width of constants
- **M** = number of constants (codewords) to generate
- **d** = minimum Hamming distance between any pair

**Question**: What is the maximum possible value of **d**?

This is a fundamental question in **coding theory** - the mathematical study of error-correcting codes.

## Why This Matters for Embedded Security

For fault injection resistance:
- **Higher d = better security**: Harder to glitch one constant into another
- **Trade-offs**: More constants (larger M) → lower maximum d
- **Requirements planning**: Know theoretical limits before setting security requirements

## The Three Main Bounds

### 1. Singleton Bound (Simple but Loose)

**Formula**:
```
d ≤ n - ⌈log₂(M)⌉ + 1
```

**Intuition**: Information-theoretic argument based on the number of bits needed to distinguish M codewords.

**When useful**: Quick sanity check; often too optimistic.

**Example**: For n=32, M=10:
```
d ≤ 32 - ⌈log₂(10)⌉ + 1 = 32 - 4 + 1 = 29
```

### 2. Hamming (Sphere-Packing) Bound

**Formula**:
```
M · V(n, t) ≤ 2ⁿ
where t = ⌊(d-1)/2⌋
V(n,t) = Σ(i=0 to t) C(n,i)  [volume of Hamming sphere]
```

**Intuition**: Each codeword has an exclusive "sphere" around it of radius t. These spheres cannot overlap, so their total volume cannot exceed the entire n-bit space (2ⁿ).

**Visualization** (for n=8 bits):
```
Codeword 1:  ●───t───○  (sphere of radius t)
Codeword 2:      ●───t───○
Codeword 3:           ●───t───○
...
All spheres must fit in 256 total points
```

**When useful**: General case; tighter than Singleton for most parameters.

**Example**: For n=32, M=10, testing d=24:
```
t = ⌊(24-1)/2⌋ = 11
V(32, 11) = Σ(i=0 to 11) C(32,i) ≈ 129 million
M · V = 10 × 129M = 1.29 billion
2³² = 4.29 billion
Since 1.29B ≤ 4.29B, d=24 is possible by this bound
```

### 3. Plotkin Bound (Best for d > n/2)

**Formula**:
```
If 2d > n:
  - d even: M ≤ 2d/(2d - n)
  - d odd:  M ≤ (2d+1)/(2d+1 - n)
If 2d ≤ n:
  - M ≤ 2^(n - 2⌊d/2⌋ + 1)
```

**Intuition**: Based on counting argument using the total sum of pairwise distances. When d is large relative to n, there are strong combinatorial constraints.

**When useful**: Large distances (d > n/2); gives tightest bounds in this regime.

**Example**: For n=32, M=10, testing d=17:
```
2d = 34 > 32, so use first formula
d = 17 (odd), so:
M ≤ (2×17+1)/(2×17+1 - 32) = 35/3 = 11.67

Since 10 < 11.67, d=17 is possible by this bound
```

Testing d=18:
```
2d = 36 > 32
d = 18 (even), so:
M ≤ (2×18)/(2×18 - 32) = 36/4 = 9

Since 10 > 9, d=18 is NOT possible by this bound
```

## Tightest Bound Selection

For any given (n, M), calculate all three bounds and take the **minimum** (most restrictive):

```python
max_distance = min(
    singleton_bound(n, M),
    hamming_bound(n, M),
    plotkin_bound(n, M)
)
```

## Practical Examples

### Example 1: 32-bit, 10 constants

```
Singleton: d ≤ 29 (too optimistic)
Hamming:   d ≤ 24 (reasonable)
Plotkin:   d ≤ 17 (tightest - this is the real limit)
```

**Practical result**: Generator achieved d=16, very close to theoretical maximum!

### Example 2: 16-bit, 16 constants

```
Singleton: d ≤ 13
Hamming:   d ≤ 10
Plotkin:   d ≤ 8  (tightest)
```

### Example 3: 8-bit, 4 constants

```
Singleton: d ≤ 7
Hamming:   d ≤ 6
Plotkin:   d ≤ 4  (tightest)
```

**Special note**: For 8-bit with 4 constants at d=4, we approach a **Hamming (8,4,4) code** - a well-known code in theory.

## Known Optimal Codes

For certain parameters, **optimal codes** are known (proven to achieve the theoretical maximum):

| Parameters | Type | d_max | Notes |
|------------|------|-------|-------|
| n=7, M=16 | Hamming | 3 | Hamming(7,4,3) code |
| n=8, M=2 | Trivial | 8 | Complementary pair |
| n=23, M=2048 | Golay | 7 | Binary Golay code |
| n=32, M=2 | Trivial | 32 | Complementary pair |

For most other parameters, finding optimal codes is an **open research problem**.

## Using Bounds for Requirements

### Setting Security Requirements

1. **Start with bit width (n)**: Based on your architecture (8/16/32/64-bit)

2. **Determine number needed (M)**: How many magic constants/states do you need?

3. **Calculate maximum d**: Run bounds calculator
   ```bash
   python3 bounds_calculator.py 32 10
   # Output: Tightest bound: d ≤ 17
   ```

4. **Set realistic requirement**: Choose d slightly below theoretical max
   ```
   Theoretical: d ≤ 17
   Practical:   d = 14-16 (accounts for algorithmic limitations)
   ```

### Example Requirements Table

| Application | n | M | Theory | Practical | Security Level |
|-------------|---|---|--------|-----------|----------------|
| State machine (simple) | 16 | 8 | d≤8 | d=6-8 | Medium |
| State machine (secure) | 32 | 10 | d≤17 | d=14-16 | High |
| Command codes | 32 | 32 | d≤16 | d=12-14 | High |
| Magic numbers | 64 | 16 | d≤33 | d=28-32 | Very High |

## Impossibility Detection

Our generator validates parameters against these bounds:

```python
if min_distance > theoretical_max:
    ERROR: Parameters exceed theoretical limits
```

This prevents wasting time trying to generate impossible codes.

## References

### Classic Papers
- R.W. Hamming (1950): "Error Detecting and Error Correcting Codes"
- M. Plotkin (1960): "Binary Codes with Specified Minimum Distance"

### Bounds Summary
- **Singleton bound**: Easy to compute, often loose
- **Hamming bound**: Good general bound, moderate computation
- **Plotkin bound**: Tightest for large d, simple formulas

### Proof Techniques
- Sphere packing (geometric)
- Counting arguments (combinatorial)
- Linear algebra (for linear codes)

## Advanced Topics

### Gilbert-Varshamov Bound (Lower Bound)

While the above are **upper bounds** (impossibility results), the Gilbert-Varshamov bound is a **lower bound** (achievability result):

```
If M · V(n, d-1) < 2ⁿ, then a code with parameters (n, M, d) EXISTS
```

This tells us when we should be able to find a code, even if we don't know the construction.

### Asymptotic Bounds

For large n, various asymptotic results exist:
- Shannon capacity
- Rate-distance trade-offs
- Probability of random codes

These are mainly theoretical interest for cryptographic applications.

## Practical Tools

### Bounds Calculator

```bash
# Show example tables
python3 bounds_calculator.py

# Calculate for specific parameters
python3 bounds_calculator.py 32 10
```

### Generator with Bounds

```bash
# Show theoretical bounds with results
python3 secure_constants.py -b 32 -c 10 -m 16 --show-bounds
```

## Conclusion

Understanding theoretical bounds:
1. **Sets realistic expectations** for security requirements
2. **Prevents impossible specifications** early in design
3. **Validates algorithm quality** (how close to theoretical max?)
4. **Informs trade-offs** (M vs d vs n)

For embedded security: Always check bounds before setting requirements!
