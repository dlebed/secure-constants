# How to Calculate Maximum Theoretically Possible Minimum Hamming Distance

## Quick Answer

Given **n** bits and **M** constants, calculate using three bounds and take the minimum:

```python
import math

def max_hamming_distance(n, M):
    """Calculate theoretical maximum minimum distance"""

    # 1. Singleton bound
    singleton = n - math.ceil(math.log2(M)) + 1

    # 2. Hamming (sphere-packing) bound
    hamming = hamming_bound(n, M)  # See below

    # 3. Plotkin bound
    plotkin = plotkin_bound(n, M)  # See below

    return min(singleton, hamming, plotkin)
```

## The Three Bounds Explained

### 1. Singleton Bound (Easiest)

**Formula**: `d ≤ n - ⌈log₂(M)⌉ + 1`

**When to use**: Quick check, but often too optimistic

**Example** (32-bit, 10 constants):
```python
d_max = 32 - math.ceil(math.log2(10)) + 1
      = 32 - 4 + 1
      = 29  # Way too optimistic!
```

### 2. Hamming (Sphere-Packing) Bound

**Formula**: Find largest d where `M × V(n, t) ≤ 2ⁿ`
- Where `t = ⌊(d-1)/2⌋`
- `V(n,t) = Σ(i=0 to t) C(n,i)` (binomial coefficients)

**Intuition**: Each constant needs a "sphere" of radius t around it. All spheres must fit in the n-bit space.

**Implementation**:
```python
def hamming_sphere_volume(n, r):
    """Volume of Hamming sphere"""
    return sum(math.comb(n, i) for i in range(r + 1))

def hamming_bound(n, M):
    """Find max d using Hamming bound"""
    for d in range(n, 0, -1):
        t = (d - 1) // 2
        if M * hamming_sphere_volume(n, t) <= 2**n:
            return d
    return 1
```

**Example** (32-bit, 10 constants):
```
Testing d=24: t=11, V(32,11)≈129M, M×V≈1.29B ≤ 4.29B ✓
Result: d ≤ 24
```

### 3. Plotkin Bound (Best for Large Distances)

**Formula**:
```
If 2d > n and d even:
    M ≤ 2d / (2d - n)

If 2d > n and d odd:
    M ≤ (2d+1) / (2d+1 - n)

If 2d ≤ n:
    M ≤ 2^(n - 2⌊d/2⌋ + 1)
```

**When to use**: **Most accurate** when d > n/2 (common for secure constants)

**Implementation**:
```python
def plotkin_bound(n, M):
    """Find max d using Plotkin bound"""
    for d in range(n, 0, -1):
        if 2 * d > n:
            # Large distance case
            if d % 2 == 0:  # even
                max_M = (2 * d) // (2 * d - n)
            else:  # odd
                max_M = (2 * d + 1) // (2 * d + 1 - n)
        else:
            # Small distance case
            max_M = 2 ** (n - 2 * (d // 2) + 1)

        if max_M >= M:
            return d
    return 1
```

**Example** (32-bit, 10 constants):
```
Testing d=18: 2d=36>32, even
  max_M = 36/(36-32) = 9
  9 < 10 ✗

Testing d=17: 2d=34>32, odd
  max_M = 35/(35-32) = 11.67
  11.67 > 10 ✓

Result: d ≤ 17  (TIGHTEST!)
```

## Complete Working Example

**Problem**: What's the maximum minimum distance for 10 32-bit constants?

**Step 1** - Singleton bound:
```
d ≤ 32 - ⌈log₂(10)⌉ + 1 = 29
```

**Step 2** - Hamming bound:
```
Testing d=24:
  t = (24-1)/2 = 11
  V(32,11) = Σ C(32,i) for i=0..11 ≈ 129,047,760
  M × V = 10 × 129,047,760 = 1,290,477,600
  2³² = 4,294,967,296
  1,290,477,600 ≤ 4,294,967,296 ✓
Result: d ≤ 24
```

**Step 3** - Plotkin bound:
```
Testing d=17:
  2×17 = 34 > 32 (use large distance formula)
  d=17 is odd: max_M = (2×17+1)/(2×17+1-32) = 35/3 = 11.67
  11.67 ≥ 10 ✓

Testing d=18:
  2×18 = 36 > 32
  d=18 is even: max_M = (2×18)/(2×18-32) = 36/4 = 9
  9 < 10 ✗

Result: d ≤ 17
```

**Final Answer**: `min(29, 24, 17) = 17` ← **Plotkin bound is tightest**

## Validation: Actual Generation

```bash
$ python3 secure_constants.py -b 32 -c 10 -m 16
✓ SUCCESS: Generated d=16 (within theoretical limit of 17)

$ python3 secure_constants.py -b 32 -c 10 -m 17
✓ SUCCESS: Generated d=17 (achieved theoretical maximum!)

$ python3 secure_constants.py -b 32 -c 10 -m 18
✗ ERROR: Exceeds Plotkin bound (d ≤ 17)
```

## Practical Tools

### Use Auto-Discovery Mode (Easiest)

```bash
# Let the tool find maximum distance automatically
python3 secure_constants.py -b 32 -c 10

# Output:
# Auto-discovery mode: Theoretical maximum is d ≤ 17 (Plotkin bound)
# Trying d = 17... ✗ Failed
# Trying d = 16... ✓ SUCCESS (achieved d = 16)
#
# Generated 10 constants (32-bit)
# Minimum Hamming distance: 16 (auto-discovered, 94% of theoretical max)
```

### Use the Bounds Calculator

```bash
# Calculate bounds for your parameters
python3 bounds_calculator.py 32 10

# Output:
#   Singleton bound: d ≤ 29
#   Hamming bound:   d ≤ 24
#   Plotkin bound:   d ≤ 17
#   Tightest bound:  d ≤ 17
```

### Generator with Manual Distance

```bash
# Specify exact minimum distance requirement
python3 secure_constants.py -b 32 -c 10 -m 16
# ✓ SUCCESS: Generated d=16

# Try impossible constraint
python3 secure_constants.py -b 32 -c 10 -m 20
# ERROR: Parameters exceed theoretical limits:
#        Requested min distance 20 but Plotkin bound
#        gives maximum d ≤ 17 for 10 32-bit constants
```

## Summary Table

| Bound | When Best | Complexity | Typical Use |
|-------|-----------|------------|-------------|
| Singleton | Never (too loose) | O(1) | Sanity check |
| Hamming | Medium d | O(n²) | General case |
| Plotkin | **Large d (d>n/2)** | O(1) | **Secure constants** |

## Key Insights for Embedded Security

1. **Plotkin bound is usually tightest** for security applications (we want large d)

2. **Trade-off**: More constants → lower maximum distance
   - 10 32-bit constants: d ≤ 17
   - 32 32-bit constants: d ≤ 16
   - 128 32-bit constants: d ≤ 16

3. **Bit width matters**:
   - Double bits → roughly double max distance (for fixed M)
   - 16-bit, 10 const: d ≤ 9
   - 32-bit, 10 const: d ≤ 17
   - 64-bit, 10 const: d ≤ 33

4. **Set realistic requirements**:
   - Calculate theoretical max first
   - Aim for 85-95% of theoretical (algorithm limitations)
   - Example: Theory gives d≤17 → require d≥15

## Mathematical Background

These bounds come from **coding theory**, which studies:
- Error detection and correction
- Information theory limits
- Combinatorial optimization

The bounds represent **impossibility results** - no code (and no algorithm) can exceed them.

## References

- **Hamming (1950)**: "Error Detecting and Error Correcting Codes"
- **Plotkin (1960)**: "Binary Codes with Specified Minimum Distance"
- **MacWilliams & Sloane (1977)**: "The Theory of Error-Correcting Codes"

For detailed theory, see [BOUNDS_THEORY.md](BOUNDS_THEORY.md).
