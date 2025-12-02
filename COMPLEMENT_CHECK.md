# Bitwise Complement Check Feature

## Overview
Added complement detection and prevention to protect against global bit-flip fault injection attacks.

## Security Rationale
If constant `A` and its bitwise complement `~A` both exist in the constant set, a single stuck-at fault affecting all bits simultaneously (e.g., voltage glitch on a shared bus, clock glitch, power supply fault) can transform one valid constant into another valid constant. This completely bypasses the security provided by Hamming distance separation.

### Example Attack Scenario
```
Constant A: 0xAAAA (10101010 10101010)
Constant B: 0x5555 (01010101 01010101)  <- bitwise complement of A

A single global fault flipping all bits:
0xAAAA → 0x5555  (A transforms into valid constant B)
```

## Implementation

### 1. Detection Function (`check_for_complements`)
```python
def check_for_complements(constants: List[int], bit_width: int) -> List[Tuple[int, int]]
```
- Checks all pairs of constants for bitwise complement relationships
- Returns list of (index_i, index_j) pairs where constants[i] == ~constants[j]
- Properly handles bit_width by masking with `(1 << bit_width) - 1`

### 2. Generation Prevention
Modified `find_best_candidate()` to reject any candidate that is the bitwise complement of an existing constant:
```python
candidate_complement = candidate ^ max_val
if candidate_complement in existing:
    continue  # Reject this candidate
```

### 3. Output Warnings
If complement pairs are detected in the final set, a CRITICAL warning is displayed:
```
======================================================================
⚠ CRITICAL: Bitwise complement pairs detected (N pairs)
======================================================================
A single stuck-at fault affecting all bits can transform one constant
into another, compromising security!

  [i]  0xAAAA  <-->  [j]  0x5555
======================================================================
```

## Testing

### Unit Tests
Five test cases verify correct detection:
1. Simple 8-bit complement pair
2. No complements in set
3. Multiple complement pairs
4. 16-bit complements
5. Mixed 32-bit values with one pair

All tests pass ✓

### Integration Test
Generated constants with various bit widths and counts show:
- No complement pairs are generated during normal operation
- Warning properly displays when complements are present in a manually constructed set

## Impact on Generation
- Slightly reduces the search space for candidates (by ~50% per constant)
- No noticeable performance impact in practice
- Improves security against global fault injection attacks
- Works seamlessly with existing Hamming distance constraints

## Example Output
```bash
$ python3 secure_constants.py --bits 16 --count 8 --min-distance 6

# Result: 8 constants generated with:
# - Minimum Hamming distance: 8
# - No weak patterns
# - No complement pairs ✓
```

## Recommendation
This check should **always** be enabled for security-critical embedded systems where fault injection attacks are a threat model.
