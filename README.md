# Secure Constant Generator

A Python utility for generating "secure" constants by maximizing Hamming distance between each other.
Designed for embedded systems security use cases to provide resistance against hardware fault injection attacks.

## Features

- **Auto-Discovery Mode**: Automatically finds maximum achievable distance
- **Architecture Optimization**: Generate constants loadable with single instruction on RISC-V RV32I or ARM Thumb-2
- **Clustering Analysis & Optimization**: Detects and prevents clustered bit differences for enhanced fault injection resistance
- **C Code Output**: Generate ready-to-use C enums or #defines with customizable prefixes
- **Weak Pattern Detection**: Automatically avoids cryptographically weak patterns (all zeros/ones, alternating bits, repeating bytes, extreme Hamming weights)
- **Maximum Hamming Distance**: Generates constants with the largest possible pairwise Hamming distances
- **Guaranteed Minimum Distance**: Enforces a required minimum distance or fails with error
- **Theoretical Bounds Validation**: Uses Singleton, Hamming, and Plotkin bounds to validate parameters
- **Flexible Bit Widths**: Supports 8 to 64-bit constants
- **Security-Focused**: Uses cryptographically secure random number generation
- **Reproducible Generation**: Optional seed parameter for deterministic output
- **Balanced Bit Distribution**: Prefers constants with roughly equal 0s and 1s for better security properties
- **Comprehensive Output**: Provides hex values, distance matrix, statistics, and clustering analysis

## Security Applications

This tool is designed for embedded systems security scenarios:

- **Fault Injection Resistance**: Constants with high Hamming distance and well-distributed bit differences make it harder to glitch one value into another
- **Localized Attack Protection**: Clustering analysis prevents concentration of bit differences in specific bytes/regions vulnerable to targeted attacks
- **State Machine Security**: Use as magic numbers for secure state transitions
- **Error Detection**: Corrupted constants are more likely to be detected
- **Command Validation**: Secure command codes that resist bit-flip attacks

## Project Files

- **secure_constants.py** - Main constant generator with theoretical bounds validation
- **bounds_calculator.py** - Standalone bounds calculator tool
- **BOUNDS_THEORY.md** - Detailed explanation of coding theory bounds
- **ARCH_OPTIMIZATION.md** - Architecture-specific optimization guide (RISC-V, ARM)
- **README.md** - This file
- **examples/** - Example outputs

## Installation

No dependencies required - uses only Python standard library (Python 3.9+):

```bash
chmod +x secure_constants.py
chmod +x bounds_calculator.py
```

## Usage

### Basic Syntax

```bash
# Auto-discover maximum distance (recommended)
python3 secure_constants.py --bits <BIT_WIDTH> --count <NUM_CONSTANTS>

# Specify minimum distance requirement
python3 secure_constants.py --bits <BIT_WIDTH> --count <NUM_CONSTANTS> --min-distance <MIN_DISTANCE>
```

### Required Arguments

- `-b, --bits`: Bit width of constants (8-64)
- `-c, --count`: Number of constants to generate

### Optional Arguments

- `-m, --min-distance`: Minimum required Hamming distance (if not specified, auto-discovers maximum)
- `-f, --format`: Output format - `default`, `c-enum`, or `c-define` (default: default)
- `-p, --prefix`: Prefix for C constant names (default: SECURE_CONST)
- `-a, --attempts`: Maximum generation attempts (default: 100)
- `--candidates`: Candidates to test per round (default: 1000)
- `-s, --seed`: Random seed for reproducibility
- `--show-bounds`: Display theoretical bounds (Singleton, Hamming, Plotkin)
- `--arch`: Architecture constraint - `riscv` (RV32I) or `arm` (Thumb-2) for single-instruction loadable constants
- `--check-clustering`: Enable clustering optimization during generation
- `--min-distribution-score`: Minimum distribution quality score when using `--check-clustering` (0-100, default: 40)
- `--show-clustering`: Display detailed clustering analysis in output

## Examples

### Auto-Discover Maximum Distance (Recommended)

```bash
python3 secure_constants.py --bits 32 --count 10
```

Output:
```
Generating 10 32-bit constants (auto-discovering maximum distance)...

Auto-discovery mode: Theoretical maximum is d ≤ 17 (Plotkin bound)
Searching for maximum achievable distance...

Trying d = 17... ✗ Failed (best: d = 16)
Trying d = 16... ✓ SUCCESS (achieved d = 16)

======================================================================
Generated 10 constants (32-bit)
Minimum Hamming distance: 16 (auto-discovered, 94% of theoretical max)
======================================================================

Constants:
  [ 0]  0x17742F78  (weight: 17)
  [ 1]  0xBCABD582  (weight: 17)
  ...
```

### Specify Minimum Distance Requirement

```bash
python3 secure_constants.py --bits 32 --count 10 --min-distance 16
```

Output:
```
Generated 10 constants (32-bit)
Minimum Hamming distance: 16

Constants:
  [ 0]  0x8A3F5C71  (weight: 16)
  [ 1]  0x45C0A38E  (weight: 14)
  ...
```

### Small Bit Width Examples

```bash
# Auto-discover for 16-bit
python3 secure_constants.py -b 16 -c 5

# Specify distance for 8-bit
python3 secure_constants.py -b 8 -c 4 -m 4
```

### Reproducible Generation

Use the `--seed` parameter to generate identical constants across runs:

```bash
# First run
python3 secure_constants.py -b 16 -c 5 -s 12345

# Second run with same seed - produces identical constants
python3 secure_constants.py -b 16 -c 5 -s 12345
```

**Use cases**:
- Version control: Track exact constants used in each firmware version
- Testing: Reproducible test vectors
- Compliance: Auditable generation process

**Note**: Without `--seed`, the tool uses cryptographically secure random generation (default behavior).

### Clustering Analysis and Optimization

Detect and prevent clustered bit differences that could make localized fault injection attacks easier.

#### Show Clustering Analysis

View distribution quality of bit differences:

```bash
python3 secure_constants.py -b 32 -c 10 --show-clustering
```

Output includes clustering report:
```
======================================================================
Bit Difference Distribution Analysis:
======================================================================

Overall Statistics (45 pairs analyzed):
  Average distribution score: 88.7/100
  Average max cluster size: 4.4 bits
  Average byte coverage: 100.0%

Quality Distribution:
  Excellent (≥80):  42 pairs (93.3%)
  Good (60-79):      3 pairs (6.7%)
  Fair (40-59):      0 pairs (0.0%)
  Poor (<40):        0 pairs (0.0%)

Best distributed pair: [ 0] vs [ 5]  Score: 94.4/100
  [ 0]: 0x7D9510A7
  [ 5]: 0xC80FC481
  XOR: 0xB59AD426

  Bit difference map (X = different, . = same):
  X.XX.X.X X..XX.X. XX.X.X.. ..X..XX.
  Byte:    3        2        1        0
```

#### Enable Clustering Optimization

Generate constants with optimized bit difference distribution:

```bash
# Enable clustering optimization (rejects poorly distributed candidates)
python3 secure_constants.py -b 32 -c 10 --check-clustering

# Use stricter threshold (higher quality requirement)
python3 secure_constants.py -b 32 -c 10 --check-clustering --min-distribution-score 70

# Show both optimization and analysis
python3 secure_constants.py -b 32 -c 10 --check-clustering --show-clustering
```

**Distribution Score Metrics:**
- **Excellent (≥80)**: Well-distributed differences across all bytes, small clusters
- **Good (60-79)**: Acceptable distribution, some clustering
- **Fair (40-59)**: Moderate clustering, may be vulnerable to localized attacks
- **Poor (<40)**: Severe clustering, high risk

**When to use:**
- **`--check-clustering`**: High-security applications where localized fault injection is a concern
- **`--show-clustering`**: Always recommended to verify bit difference quality
- **`--min-distribution-score`**: Set based on security requirements (40-70 typical)

### Architecture-Optimized Constants (Single-Instruction Loading)

Generate constants that can be loaded with a **single 32-bit instruction** on embedded processors, combining code efficiency with security.

#### RISC-V RV32I

```bash
python3 secure_constants.py -b 32 -c 10 --arch riscv
```

Generates constants loadable with single `ADDI` or `LUI` instructions:
- **Valid set**: ~1,052,671 values (0.024% of 2³²)
- **ADDI range**: `[-2048, 2047]` → `addi rd, zero, imm`
- **LUI range**: Multiples of 4096 → `lui rd, imm20`
- **Typical Hamming distance**: 9-13 for 10 constants

Output includes instruction encodings:
```
Architecture: RISCV - Single-Instruction Loadable
Valid set size: 1,052,671 values (0.0245% of 2^32)

Instruction encodings:
  [ 0]  0x1118A000  →  lui rd, 0x1118A
  [ 1]  0xFFFFFFFD  →  addi rd, zero, -3
  [ 2]  0xAEF35000  →  lui rd, 0xAEF35
  ...
```

#### ARM Thumb-2

```bash
python3 secure_constants.py -b 32 -c 10 --arch arm
```

Generates constants loadable with single `MOVW`, `MOV`, or `MVN` instructions:
- **Valid set**: ~68,774 values (0.0016% of 2³²)
- **MOVW**: 16-bit immediate zero-extended → `movw r0, #imm16`
- **MOV**: Modified immediate patterns → `mov r0, #imm`
- **MVN**: Bitwise NOT of modified immediate → `mvn r0, #imm`
- **Typical Hamming distance**: 12-16 for 10 constants

Output includes instruction encodings:
```
Architecture: ARM - Single-Instruction Loadable
Valid set size: 68,774 values (0.0016% of 2^32)

Instruction encodings:
  [ 0]  0x0000D5AE  →  movw r0, #0xD5AE
  [ 1]  0xFFFFFF40  →  mvn r0, #0x000000BF
  [ 2]  0x00FF0000  →  mov r0, #0x00FF0000
  ...
```

#### With C Output Format

Combine architecture optimization with C code generation:

```bash
python3 secure_constants.py -b 32 -c 10 --arch riscv --format c-enum --prefix STATE
```

Generates ready-to-use C code with instruction comments:
```c
enum SecureConstants {
    STATE_00 = 0x1118A000UL,  /* weight: 6, lui rd, 0x1118A */
    STATE_01 = 0xFFFFFFFDUL,  /* weight: 31, addi rd, zero, -3 */
    ...
};
```

**Benefits:**
- ✅ Reduced code size (no multi-instruction sequences)
- ✅ Faster execution (fewer CPU cycles)
- ✅ Maintains high Hamming distance for security (typically 9-16 bits)
- ✅ No instruction cache pollution

**See [ARCH_OPTIMIZATION.md](ARCH_OPTIMIZATION.md) for detailed technical specifications.**

### C Code Output Formats

When using `--format c-enum` or `--format c-define`, the utility shows:
1. **All normal statistics** (constants list, Hamming distance matrix)
2. **C formatted code** at the end (ready to copy/paste into header files)

#### C Enumeration Format

```bash
python3 secure_constants.py -b 8 -c 4 -m 4 --format c-enum
```

Output includes full statistics, then:
```
======================================================================
C Enumeration Format:
======================================================================

/* Auto-generated secure constants (8-bit, 4 values) */
/* Minimum Hamming distance: 4 */
/* Type: uint8_t */

enum SecureConstants {
    SECURE_CONST_00 = 0x36U,  /* weight: 4 */
    SECURE_CONST_01 = 0xC9U,  /* weight: 4 */
    SECURE_CONST_02 = 0xD7U,  /* weight: 6 */
    SECURE_CONST_03 = 0x9CU,  /* weight: 4 */
};
```

#### C #define Format

```bash
python3 secure_constants.py -b 16 -c 5 --format c-define
```

Output includes full statistics, then:
```
======================================================================
C #define Format:
======================================================================

/* Auto-generated secure constants (16-bit, 5 values) */
/* Minimum Hamming distance: 8 */
/* Type: uint16_t */

#define SECURE_CONST_00  0xE4DCU  /* weight: 9 */
#define SECURE_CONST_01  0x1763U  /* weight: 8 */
#define SECURE_CONST_02  0xB88BU  /* weight: 8 */
#define SECURE_CONST_03  0x7A35U  /* weight: 9 */
#define SECURE_CONST_04  0x8FBDU  /* weight: 11 */
```

#### Custom Prefix for C Output

Use `--prefix` to customize constant names for your application:

```bash
python3 secure_constants.py -b 16 -c 4 --format c-enum --prefix FSM_STATE
```

Output:
```c
enum SecureConstants {
    FSM_STATE_00 = 0x473BU,  /* weight: 9 */
    FSM_STATE_01 = 0x78C0U,  /* weight: 6 */
    FSM_STATE_02 = 0x8ED5U,  /* weight: 9 */
    FSM_STATE_03 = 0x882EU,  /* weight: 6 */
};
```

**Features of C output formats**:
- Shows complete statistics and distance matrix first
- C code appears at the end for easy extraction
- Proper type suffixes: `U` (8/16-bit), `UL` (32-bit), `ULL` (64-bit)
- Comments with Hamming weight for each constant
- Header comment with total count and minimum distance
- Customizable prefix for application-specific naming (e.g., `STATE_`, `CMD_`, `MAGIC_`)

### Handle Impossible Constraints

```bash
python3 secure_constants.py -b 8 -c 100 -m 4
```

Output:
```
ERROR: Parameters likely impossible: 100 constants with min distance 4
in 8 bits exceeds theoretical bounds

Suggestions:
  - Reduce minimum distance requirement
  - Reduce number of constants
  - Increase bit width
```

## Auto-Discovery Mode

When the `--min-distance` parameter is **not specified**, the utility enters **auto-discovery mode**:

1. **Calculates theoretical maximum** using coding theory bounds (Singleton, Hamming, Plotkin)
2. **Attempts generation** starting from theoretical maximum
3. **Falls back by 1** if generation fails, and tries again
4. **Reports efficiency** as percentage of theoretical maximum achieved

### How It Works

```
Theoretical max: d ≤ 17 (Plotkin bound)
  ↓
Try d=17 → Failed
  ↓
Try d=16 → SUCCESS ✓

Result: d=16 (94% of theoretical max)
```

### When to Use Auto-Discovery

**Recommended for**:
- Initial exploration: "What's the best I can get?"
- Production use: Maximum security for given parameters
- Benchmarking: Compare to theoretical limits

**Use manual mode when**:
- You have specific compliance requirements (e.g., "must have d ≥ 14")
- You want faster generation (skip attempts at higher distances)
- You're debugging or testing specific scenarios

### Performance

Auto-discovery typically achieves:
- **85-100% of theoretical maximum** (often 94-100%)
- **1-3 fallback attempts** before success
- **Similar runtime** to manual mode (usually succeeds on first or second try)

## Exit Codes

- **0**: Success - all constants generated meeting minimum distance requirement
- **1**: Failed to meet minimum distance constraint after all attempts
- **2**: Invalid arguments (e.g., impossible parameters)

## Algorithm

The utility uses a **greedy algorithm with random restart**:

1. Start with a random balanced constant (Hamming weight ≈ n/2)
2. For each subsequent constant:
   - Test multiple random candidates
   - Select the one with maximum minimum distance to existing constants
   - Fail if no candidate meets the minimum distance requirement
3. Repeat with different random seeds if needed
4. Return the first successful set or the best attempt

### Security Properties

- Uses `secrets.SystemRandom()` for cryptographically secure randomness (or `random.Random(seed)` when seed specified)
- **Weak pattern detection**: Automatically rejects constants with cryptographically weak patterns:
  - All zeros or all ones
  - Alternating bit patterns (0xAAAA, 0x5555)
  - Repeating bytes (0x12121212)
  - Sequential nibble patterns
  - Extreme Hamming weights (too few or too many bits set)
- Prefers balanced constants to avoid degenerate patterns
- Validates uniqueness of all generated constants

## Theoretical Limits

The number of constants possible with a given minimum distance is bounded by **error-correcting code theory**. The utility automatically checks these bounds and prevents impossible parameter combinations.

### Three Main Bounds

1. **Singleton Bound**: `d ≤ n - ⌈log₂(M)⌉ + 1` (simple but loose)
2. **Hamming Bound**: `M · V(n, ⌊(d-1)/2⌋) ≤ 2ⁿ` (sphere-packing argument)
3. **Plotkin Bound**: Tightest for large distances (d > n/2)

The utility uses the **tightest** (most restrictive) bound to validate parameters before generation.

### Example Limits

| Bit Width | Constants | Max Distance (Theory) | Bound Type |
|-----------|-----------|----------------------|------------|
| 8-bit     | 4         | d ≤ 4                | Plotkin    |
| 8-bit     | 16        | d ≤ 4                | Hamming    |
| 16-bit    | 8         | d ≤ 8                | Plotkin    |
| 16-bit    | 16        | d ≤ 8                | Plotkin    |
| 32-bit    | 10        | d ≤ 17               | Plotkin    |
| 32-bit    | 32        | d ≤ 16               | Plotkin    |
| 64-bit    | 16        | d ≤ 33               | Plotkin    |

**Note**: Greedy algorithm typically achieves 85-95% of theoretical maximum.

### Bounds Calculator Tool

Calculate theoretical limits for your parameters:

```bash
# Show example tables for 8/16/32-bit
python3 bounds_calculator.py

# Calculate specific case
python3 bounds_calculator.py 32 10
# Output: Tightest bound: d ≤ 17
```

### Show Bounds with Generation

```bash
python3 secure_constants.py -b 32 -c 10 -m 16 --show-bounds
```

This displays all three bounds alongside your results.

### Further Reading

See [BOUNDS_THEORY.md](BOUNDS_THEORY.md) for detailed mathematical explanations, proofs, and practical guidance on using theoretical bounds for security requirements.

## Best Practices for Embedded Security

1. **Minimum Distance Selection**:
   - For basic error detection: min_distance ≥ 3 (detects 2-bit flips)
   - For fault injection resistance: min_distance ≥ 8-12
   - For high security: min_distance ≥ bit_width/2

2. **Bit Width Selection**:
   - 8-bit: Suitable for simple state machines (limited constants)
   - 16-bit: Good balance for most applications
   - 32-bit: High security applications
   - 64-bit: Maximum security, many constants possible

3. **Integration**:
   - Store constants in read-only memory (ROM/Flash)
   - Validate against all invalid values, not just specific constants
   - Use with redundant checks in critical code paths

4. **Clustering Analysis**:
   - Always use `--show-clustering` to verify bit difference distribution quality
   - For high-security applications, enable `--check-clustering` during generation
   - Target distribution scores: ≥80 for excellent, ≥60 for good security
   - Adjust `--min-distribution-score` based on threat model (40-70 typical range)
   - Pay attention to byte coverage - 100% coverage provides best protection against localized attacks

5. **C Code Generation**:
   - Use `--format c-enum` for type-safe enumerations
   - Use `--format c-define` for preprocessor constants
   - Use `--prefix` to customize constant names (e.g., `--prefix STATE` for `STATE_00`, `STATE_01`)
   - Always review statistics to verify minimum distance achieved
   - C code appears at end of output for easy copying to header files
   - Include generated header in your embedded firmware project
   - Use `--seed` for reproducible builds tracked in version control

## Integrating into Embedded Projects

### Generate C Header File

The C output formats show all statistics for verification, then provide ready-to-use C code at the end:

```bash
# View statistics and C code together
python3 secure_constants.py -b 32 -c 10 -m 16 --format c-enum

# Save entire output to review statistics
python3 secure_constants.py -b 32 -c 10 -m 16 --format c-enum > output.txt

# Copy just the C code section from the output to your header file
# (The C code appears after the statistics at the end)
```

**Workflow**:
1. Run with `--format c-enum` to see statistics and verify quality
2. Scroll to the bottom where "C Enumeration Format:" section appears
3. Copy the C code (from `/* Auto-generated...` to `};`) into your header file

### Use in C Code

```c
#include "secure_constants.h"

typedef enum {
    STATE_IDLE = SECURE_CONST_00,
    STATE_AUTH = SECURE_CONST_01,
    STATE_EXEC = SECURE_CONST_02,
    // ...
} secure_state_t;

// Validate state transitions with high Hamming distance protection
if (current_state == STATE_IDLE && next_state == STATE_AUTH) {
    // Proceed with authentication
}
```

## Troubleshooting

### "Could not generate X constants with minimum distance Y"

- Reduce the minimum distance requirement
- Reduce the number of constants needed
- Increase bit width
- Increase `--attempts` and `--candidates` (slower but better chance)

### "Parameters likely impossible"

The requested parameters exceed known theoretical bounds. Adjust your requirements.

## License

This utility is provided as-is under BSD-2-Clause license.

