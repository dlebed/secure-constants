# Constant Verification Mode

## Overview
Verification mode allows you to analyze existing sets of constants for security vulnerabilities without generating new ones. This is useful for:
- Auditing manually-created constants
- Verifying constants from legacy code
- Checking constants from external sources
- Validating code review findings

## Usage

### Basic Verification
```bash
python3 secure_constants.py --verify constants.txt
```

Auto-detects bit width from the maximum value in the file.

### With Explicit Bit Width
```bash
python3 secure_constants.py --verify constants.txt --bits 32
```

Useful when constants should be evaluated at a specific bit width.

### With Clustering Analysis
```bash
python3 secure_constants.py --verify constants.txt --show-clustering
```

Includes detailed bit difference distribution analysis.

## Supported Input Formats

The parser supports multiple formats automatically:

### Hexadecimal
```
0xABCD      # Standard C/Python format
0XABCD      # Uppercase prefix
ABCDh       # Assembly style
$ABCD       # Dollar prefix
```

### Decimal
```
12345       # Plain decimal numbers
```

### Binary
```
0b10101010  # Standard binary
1010b       # Assembly binary
```

### C Header Files
```c
#define STATE_INIT    0x1234
#define STATE_READY   0x5678

enum Status {
    STATUS_OK    = 0xABCD,
    STATUS_ERROR = 0xDEF0
};
```

### Comments
```
// C++ style comments
# Shell/Python style comments
/* C-style block comments */
```

## Verification Report

The report includes:

1. **Constants List**: All loaded values with weights
2. **Hamming Distance Statistics**: Min/max/average distances
3. **Theoretical Bounds**: Comparison with coding theory limits
4. **Weak Pattern Detection**: Identifies security-weak patterns
5. **Complement Check**: Critical vulnerability detection
6. **Distance Matrix**: Pairwise Hamming distances
7. **Clustering Analysis** (optional): Bit distribution quality
8. **Final Verdict**: PASS/FAIL with issue summary

## Example: Good Constants

File: `constants_good.txt`
```
0x39
0xD6
0x6C
0xCB
0x85
```

Result:
```
✓ VERIFICATION PASSED
No critical security issues detected.

Hamming Distance Statistics:
  Minimum distance: 4
  Maximum distance: 7
  Average distance: 4.80
  Efficiency: 100.0% of theoretical maximum
```

## Example: Bad Constants

File: `constants_bad.txt`
```
0xAA    // Weak: alternating pattern
0x55    // Complement of 0xAA
0x00    // Weak: all zeros
0xFF    // Weak: all ones
```

Result:
```
✗ VERIFICATION FAILED
Issues found (2):
  - 4 weak patterns detected
  - 2 complement pairs detected (CRITICAL)

⚠ CRITICAL: Bitwise Complement Pairs (2 pairs)
A single stuck-at fault affecting all bits can transform one constant
into another, compromising security!

  [0] 0xAA <--> [1] 0x55
  [2] 0x00 <--> [3] 0xFF
```

## Security Issues Detected

### 1. Weak Patterns
- All zeros (`0x00`)
- All ones (`0xFF`)
- Alternating bits (`0xAA`, `0x55`)
- Repeating bytes (`0x1111`)
- Sequential patterns
- Unbalanced Hamming weight

### 2. Complement Pairs (CRITICAL)
Constants where `A = ~B`. A global bit-flip fault can transform one valid constant into another.

### 3. Poor Bit Clustering
Bit differences concentrated in small regions, making localized fault injection easier.

### 4. Duplicates
Identical constants in the set.

### 5. Suboptimal Distance
Hamming distance much lower than theoretical maximum.

## Exit Codes

- `0`: Verification passed (no issues)
- `1`: Verification failed (issues detected)
- `2`: Error (file not found, parse error, etc.)

## Integration with CI/CD

```bash
#!/bin/bash
# Verify constants as part of build process

if ! python3 secure_constants.py --verify src/secure_constants.h; then
    echo "ERROR: Constant verification failed!"
    exit 1
fi

echo "Constants verified successfully"
```

## Best Practices

1. **Always verify** constants used in security-critical code
2. **Run verification** before code commits
3. **Use clustering analysis** for high-security applications
4. **Set bit width explicitly** to match your target architecture
5. **Document** the expected minimum Hamming distance
6. **Regenerate** constants if verification fails

## Comparison with Generation Mode

| Feature | Generation | Verification |
|---------|-----------|--------------|
| Creates new constants | ✓ | ✗ |
| Analyzes existing constants | ✗ | ✓ |
| Requires bit width | Required | Auto-detect |
| Requires count | Required | From file |
| File parsing | ✗ | ✓ |
| Exit code based on quality | Success only | Pass/Fail |
