# Architecture-Optimized Constant Generation

## Overview

This feature extends the Secure Constant Generator to produce constants that can be loaded with **single 32-bit instructions** on RISC-V RV32I and ARM Thumb-2 architectures, while still maintaining maximum Hamming distance for fault injection resistance.

## Motivation

In embedded systems, code density matters:
- **Two-instruction loading** (e.g., LUI + ADDI on RISC-V, or MOVW + MOVT on ARM) increases code size
- **Single-instruction loading** reduces firmware size and improves performance
- Combining security (high Hamming distance) with efficiency (single instruction) provides optimal embedded code

## Supported Architectures

### RISC-V RV32I

**Valid Set Size:** ~1,052,671 values (0.024% of 2³²)

**Single-Instruction Loadable Values:**
1. **ADDI** range: `[-2048, 2047]` (4,096 values)
   - As 32-bit hex: `0x00000000`-`0x000007FF`, `0xFFFFF800`-`0xFFFFFFFF`
   - Example: `0xFFFFFFFD` → `addi rd, zero, -3`

2. **LUI** range: Multiples of 4096 (1,048,576 values)
   - Values: `0x00000000`, `0x00001000`, `0x00002000`, ..., `0xFFFFF000`
   - Example: `0x12345000` → `lui rd, 0x12345`

### ARM Thumb-2

**Valid Set Size:** ~68,774 values (0.0016% of 2³²)

**Single-Instruction Loadable Values:**
1. **MOVW** (T3 encoding): Any 16-bit immediate zero-extended (65,536 values)
   - Range: `0x00000000`-`0x0000FFFF`
   - Example: `0x0000D5AE` → `movw r0, #0xD5AE`

2. **MOV** (T2 encoding): Modified immediate patterns (~2,003 values)
   - Rotated 8-bit values with bit 7 set
   - Patterns: `0x00XY00XY`, `0xXY00XY00`, `0xXYXYXYXY`, etc.
   - Example: `0x3C3C3C3C` → `mov r0, #0x3C3C3C3C`

3. **MVN**: Bitwise NOT of modified immediate patterns (~2,003 values)
   - Example: `0xFFFFFF40` → `mvn r0, #0x000000BF`

## Usage

### Command Line

```bash
# Generate RISC-V optimized constants
python3 secure_constants.py -b 32 -c 10 --arch riscv

# Generate ARM optimized constants
python3 secure_constants.py -b 32 -c 10 --arch arm

# With C output format
python3 secure_constants.py -b 32 -c 10 --arch riscv --format c-enum --prefix STATE

# With specific minimum distance
python3 secure_constants.py -b 32 -c 10 --arch arm -m 12
```

### Example Output

```
Architecture mode: RISCV
Pre-computing valid instruction set... done (1,052,671 valid values)

Generating 10 32-bit constants (auto-discovering maximum distance)...

Auto-discovery mode with RISCV constraints:
Valid set size: 1052671 values
Searching for maximum achievable distance with architecture constraints...

Trying d = 17... ✗ Failed
Trying d = 16... ✗ Failed
...
Trying d = 10... ✓ SUCCESS (achieved d = 10)

======================================================================
Generated 10 constants (32-bit)
Minimum Hamming distance: 10 (auto-discovered, 59% of theoretical max)
======================================================================

Constants:
  [ 0]  0x1118A000  (weight: 6)
  [ 1]  0xFFFFFFFD  (weight: 31)
  [ 2]  0xAEF35000  (weight: 13)
  ...

======================================================================
Architecture: RISCV - Single-Instruction Loadable
======================================================================
Valid set size: 1,052,671 values (0.0245% of 2^32)

Instruction encodings:
  [ 0]  0x1118A000  →  lui rd, 0x1118A
  [ 1]  0xFFFFFFFD  →  addi rd, zero, -3
  [ 2]  0xAEF35000  →  lui rd, 0xAEF35
  ...

✓ All 10 constants loadable in single RISCV instruction
======================================================================
```

## Performance Characteristics

### RISC-V RV32I

| Constants | Typical Max Distance | Valid Set Utilization |
|-----------|---------------------|----------------------|
| 5         | 12-14              | < 0.001%            |
| 10        | 9-11               | < 0.001%            |
| 20        | 7-9                | < 0.002%            |

### ARM Thumb-2

| Constants | Typical Max Distance | Valid Set Utilization |
|-----------|---------------------|----------------------|
| 5         | 15-17              | < 0.01%             |
| 10        | 12-14              | < 0.02%             |
| 20        | 9-11               | < 0.03%             |

**Note:** ARM achieves slightly better Hamming distances despite smaller valid set, due to better distribution of modified immediate patterns across the 32-bit space.

## Trade-offs

### Advantages
- ✅ Single-instruction loading (reduced code size)
- ✅ No instruction cache pollution from multi-instruction sequences
- ✅ Faster execution (fewer cycles)
- ✅ Still maintains high Hamming distance for security

### Limitations
- ⚠️ Lower maximum achievable Hamming distance (vs unconstrained generation)
  - RISC-V: Typically 30-60% of theoretical maximum
  - ARM: Typically 60-80% of theoretical maximum
- ⚠️ Some weak pattern warnings are expected (e.g., ARM modified immediates produce repeating bytes)
- ⚠️ Very small valid set (< 0.025% of 2³² space)

## Security Considerations

Even with architecture constraints:
- Minimum Hamming distance of 8-10+ is achievable for most use cases
- This is sufficient for fault injection resistance in most embedded security scenarios
- The benefit of single-instruction loading (reduced attack surface, simpler code) often outweighs slightly lower Hamming distance

## Implementation Details

### Key Functions

1. **Constraint Checkers:**
   - `is_riscv_single_instruction(value)` - Check if value is RV32I loadable
   - `is_arm_single_instruction(value)` - Check if value is Thumb-2 loadable
   - `is_arm_modified_immediate(value)` - Check ARM modified immediate encoding

2. **Pre-computation:**
   - `precompute_riscv_valid_set()` - Generate all ~1M valid RISC-V values
   - `precompute_arm_valid_set()` - Generate all ~69k valid ARM values

3. **Candidate Generation:**
   - `generate_riscv_candidate(rng)` - Generate random RISC-V loadable value
   - `generate_arm_candidate(rng)` - Generate random ARM loadable value

4. **Instruction Description:**
   - `describe_riscv_instruction(value)` - Return RV32I assembly
   - `describe_arm_instruction(value)` - Return Thumb-2 assembly

### ARM Modified Immediate Encoding

The ARM Thumb-2 modified immediate uses a 12-bit encoding `i:imm3:a:bcdefgh`:

- **Mode 0** (`imm3:a=0000`): `0x000000XY`
- **Mode 1** (`imm3:a=0001`): `0x00XY00XY`
- **Mode 2** (`imm3:a=0010`): `0xXY00XY00`
- **Mode 3** (`imm3:a=0011`): `0xXYXYXYXY`
- **Modes 4-15**: 8-bit value `1bcdefgh` rotated right by `2×imm3a` bits

This encoding produces ~2,003 unique patterns, plus another ~2,003 via MVN.

## Examples

### State Machine Constants

```c
/* RISC-V optimized state machine */
enum SecureStates {
    STATE_IDLE   = 0x1118A000UL,  /* lui rd, 0x1118A */
    STATE_AUTH   = 0xFFFFFFFDUL,  /* addi rd, zero, -3 */
    STATE_EXEC   = 0xAEF35000UL,  /* lui rd, 0xAEF35 */
    STATE_ERROR  = 0x000007FFUL,  /* addi rd, zero, 2047 */
};

/* Minimum Hamming distance: 10 bits */
```

### Command Validation

```c
/* ARM Thumb-2 optimized command codes */
#define CMD_READ   0x0000D5AEUL  /* movw r0, #0xD5AE */
#define CMD_WRITE  0xFFFFFF40UL  /* mvn r0, #0x000000BF */
#define CMD_ERASE  0x00FF0000UL  /* mov r0, #0x00FF0000 */
#define CMD_VERIFY 0x3C3C3C3CUL  /* mov r0, #0x3C3C3C3C */

/* Minimum Hamming distance: 16 bits */
```

## Future Enhancements

Potential improvements:
- Support for 64-bit architectures (RV64I, AArch64)
- Support for compressed RISC-V instructions (C extension)
- Optimization hints for specific CPU micro-architectures
- Analysis of instruction encoding collisions

## References

- RISC-V Instruction Set Manual Volume I: User-Level ISA
- ARM Architecture Reference Manual ARMv7-A/R Edition (Section A5.3.2)
- "Encoding of immediate values on AArch64" - Dominik's Blog
- Stack Overflow: RISC-V build 32-bit constants with LUI and ADDI

## Author

Implementation: Claude Sonnet 4.5
Project: Secure Constant Generator
Date: December 2025
