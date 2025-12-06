Architecture mode: ARM
Pre-computing valid instruction set... done (68,774 valid values)

Generating 8 32-bit constants (auto-discovering maximum distance)...
(Testing up to 100 attempts with 1000 candidates per round)

Auto-discovery mode with ARM constraints:
Valid set size: 68774 values
Unconstrained theoretical maximum is d ≤ 18 (Plotkin bound)
Searching for maximum achievable distance with architecture constraints...

Trying d = 18... ✗ Failed (best: d = 31)
Trying d = 17... ✗ Failed (best: d = 31)
Trying d = 16... ✗ Failed (best: d = 31)
Trying d = 15... ✓ SUCCESS (achieved d = 15)


======================================================================
Generated 8 constants (32-bit)
Minimum Hamming distance: 15 (auto-discovered, 83% of theoretical max)
======================================================================

Constants:
  [ 0]  0x0000F05E  (weight: 9)
  [ 1]  0xFFFF0FFF  (weight: 28)
  [ 2]  0x6F006F00  (weight: 12)
  [ 3]  0x00FF0000  (weight: 8)
  [ 4]  0xE4E4E4E4  (weight: 16)
  [ 5]  0xA3A3A3A3  (weight: 16)
  [ 6]  0x95959595  (weight: 16)
  [ 7]  0x3C3C3C3C  (weight: 16)

======================================================================
Statistics:
  Minimum distance: 15
  Maximum distance: 27
  Average distance: 17.46
======================================================================

======================================================================
Architecture: ARM - Single-Instruction Loadable
======================================================================
Valid set size: 68,774 values (0.0016% of 2^32)

Instruction encodings:
  [ 0]  0x0000F05E  →  movw r0, #0xF05E
  [ 1]  0xFFFF0FFF  →  mvn r0, #0x0000F000
  [ 2]  0x6F006F00  →  mov r0, #0x6F006F00
  [ 3]  0x00FF0000  →  mov r0, #0x00FF0000
  [ 4]  0xE4E4E4E4  →  mvn r0, #0x1B1B1B1B
  [ 5]  0xA3A3A3A3  →  mvn r0, #0x5C5C5C5C
  [ 6]  0x95959595  →  mvn r0, #0x6A6A6A6A
  [ 7]  0x3C3C3C3C  →  mov r0, #0x3C3C3C3C

✓ All 8 constants loadable in single ARM instruction
======================================================================

======================================================================
WARNING: Weak patterns detected (5 constants)
======================================================================
  [ 1]  0xFFFF0FFF  - too many ones (28/32)
  [ 4]  0xE4E4E4E4  - repeating bytes (0xE4)
  [ 5]  0xA3A3A3A3  - repeating bytes (0xA3)
  [ 6]  0x95959595  - repeating bytes (0x95)
  [ 7]  0x3C3C3C3C  - repeating bytes (0x3C)
======================================================================

Hamming Distance Matrix:
      [ 0] [ 1] [ 2] [ 3] [ 4] [ 5] [ 6] [ 7] 
[ 0]    -   27  17  17  15  19  17  15 
[ 1]   27   -   20  20  18  16  16  16 
[ 2]   17  20   -   20  16  16  20  16 
[ 3]   17  20  20   -   16  16  16  16 
[ 4]   15  18  16  16   -   16  16  16 
[ 5]   19  16  16  16  16   -   16  24 
[ 6]   17  16  20  16  16  16   -   16 
[ 7]   15  16  16  16  16  24  16   -  

======================================================================
C #define Format:
======================================================================

/* Auto-generated secure constants (32-bit, 8 values) */
/* Minimum Hamming distance: 15 */
/* Type: uint32_t */

#define CMD_00  0x0000F05EUL  /* weight: 9 */
#define CMD_01  0xFFFF0FFFUL  /* weight: 28 */
#define CMD_02  0x6F006F00UL  /* weight: 12 */
#define CMD_03  0x00FF0000UL  /* weight: 8 */
#define CMD_04  0xE4E4E4E4UL  /* weight: 16 */
#define CMD_05  0xA3A3A3A3UL  /* weight: 16 */
#define CMD_06  0x95959595UL  /* weight: 16 */
#define CMD_07  0x3C3C3C3CUL  /* weight: 16 */

