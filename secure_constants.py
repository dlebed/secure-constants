#!/usr/bin/env python3
"""
Secure Constant Generator
Generates a set of constants with maximum Hamming distance between each other.
Designed for embedded systems security to resist fault injection attacks.
"""

import sys
import argparse
import secrets
import random
import math
from typing import List, Tuple, Optional, Union
from dataclasses import dataclass


@dataclass
class GenerationResult:
    """Result of constant generation attempt"""
    constants: List[int]
    min_distance: int
    max_distance: int
    avg_distance: float
    success: bool


def hamming_distance(a: int, b: int) -> int:
    """
    Calculate Hamming distance between two integers.

    Args:
        a: First integer
        b: Second integer

    Returns:
        Number of differing bits
    """
    xor = a ^ b
    return bin(xor).count('1')


def calculate_min_distance(constants: List[int]) -> int:
    """
    Calculate minimum Hamming distance in a set of constants.

    Args:
        constants: List of constants

    Returns:
        Minimum pairwise Hamming distance
    """
    if len(constants) < 2:
        return 0

    min_dist = float('inf')
    for i in range(len(constants)):
        for j in range(i + 1, len(constants)):
            dist = hamming_distance(constants[i], constants[j])
            min_dist = min(min_dist, dist)

    return int(min_dist)


def calculate_distance_matrix(constants: List[int]) -> List[List[int]]:
    """
    Calculate full Hamming distance matrix.

    Args:
        constants: List of constants

    Returns:
        NxN matrix of pairwise distances
    """
    n = len(constants)
    matrix = [[0] * n for _ in range(n)]

    for i in range(n):
        for j in range(i + 1, n):
            dist = hamming_distance(constants[i], constants[j])
            matrix[i][j] = dist
            matrix[j][i] = dist

    return matrix


def calculate_statistics(constants: List[int]) -> Tuple[int, int, float]:
    """
    Calculate distance statistics.

    Args:
        constants: List of constants

    Returns:
        Tuple of (min_distance, max_distance, avg_distance)
    """
    if len(constants) < 2:
        return 0, 0, 0.0

    distances = []
    for i in range(len(constants)):
        for j in range(i + 1, len(constants)):
            distances.append(hamming_distance(constants[i], constants[j]))

    return min(distances), max(distances), sum(distances) / len(distances)


# =============================================================================
# Weak Pattern Detection
# =============================================================================

def is_weak_pattern(value: int, bit_width: int) -> Tuple[bool, Optional[str]]:
    """
    Check if a constant has weak patterns that reduce security.

    Weak patterns include:
    - All zeros or all ones
    - Alternating bits (0xAAAA, 0x5555)
    - Repeating bytes
    - Very low or high Hamming weight
    - Sequential patterns

    Args:
        value: Constant to check
        bit_width: Bit width of constant

    Returns:
        Tuple of (is_weak, reason)
    """
    max_val = (1 << bit_width) - 1

    # Check all zeros
    if value == 0:
        return True, "all zeros"

    # Check all ones
    if value == max_val:
        return True, "all ones"

    # Check Hamming weight (should be reasonably balanced)
    weight = bin(value).count('1')
    min_acceptable = bit_width // 4  # At least 25% ones
    max_acceptable = bit_width - min_acceptable  # At most 75% ones

    if weight < min_acceptable:
        return True, f"too few ones ({weight}/{bit_width})"
    if weight > max_acceptable:
        return True, f"too many ones ({weight}/{bit_width})"

    # Check alternating patterns
    if bit_width >= 8:
        # 0xAAAA pattern (10101010...)
        alternating_10 = 0
        for i in range(bit_width):
            if i % 2 == 1:
                alternating_10 |= (1 << i)

        # 0x5555 pattern (01010101...)
        alternating_01 = 0
        for i in range(bit_width):
            if i % 2 == 0:
                alternating_01 |= (1 << i)

        if value == alternating_10:
            return True, "alternating bits (0xAAAA pattern)"
        if value == alternating_01:
            return True, "alternating bits (0x5555 pattern)"

    # Check for repeating bytes (8-bit and larger)
    if bit_width >= 16:
        byte_mask = 0xFF
        first_byte = value & byte_mask
        is_repeating = True

        for i in range(1, bit_width // 8):
            current_byte = (value >> (i * 8)) & byte_mask
            if current_byte != first_byte:
                is_repeating = False
                break

        if is_repeating:
            return True, f"repeating bytes (0x{first_byte:02X})"

    # Check for sequential patterns (for 16-bit and larger)
    if bit_width >= 16:
        # Check if nibbles are sequential
        nibbles = []
        for i in range(bit_width // 4):
            nibble = (value >> (i * 4)) & 0xF
            nibbles.append(nibble)

        # Check ascending or descending sequence
        if len(nibbles) >= 4:
            is_ascending = all(nibbles[i] + 1 == nibbles[i + 1] for i in range(len(nibbles) - 1))
            is_descending = all(nibbles[i] - 1 == nibbles[i + 1] for i in range(len(nibbles) - 1))

            if is_ascending:
                return True, "sequential ascending nibbles"
            if is_descending:
                return True, "sequential descending nibbles"

    return False, None


def check_set_for_weak_patterns(constants: List[int], bit_width: int) -> List[Tuple[int, int, str]]:
    """
    Check entire set for weak patterns.

    Args:
        constants: List of constants
        bit_width: Bit width of constants

    Returns:
        List of (index, value, reason) for weak patterns found
    """
    weak_patterns = []

    for i, const in enumerate(constants):
        is_weak, reason = is_weak_pattern(const, bit_width)
        if is_weak:
            weak_patterns.append((i, const, reason))

    return weak_patterns


# =============================================================================
# Theoretical Bounds Calculators
# =============================================================================

def hamming_sphere_volume(n: int, r: int) -> int:
    """
    Calculate the volume of a Hamming sphere of radius r in n-dimensional space.

    Volume V(n,r) = Σ(i=0 to r) C(n,i) where C(n,i) is binomial coefficient.

    Args:
        n: Number of dimensions (bit width)
        r: Radius of sphere

    Returns:
        Volume of Hamming sphere
    """
    if r > n:
        return 2 ** n

    volume = 0
    for i in range(r + 1):
        volume += math.comb(n, i)

    return volume


def singleton_bound_max_distance(n: int, M: int) -> int:
    """
    Calculate maximum distance using Singleton bound.

    Singleton bound: d ≤ n - ⌈log₂(M)⌉ + 1

    This is a simple bound but often loose.

    Args:
        n: Bit width
        M: Number of codewords

    Returns:
        Maximum minimum distance by Singleton bound
    """
    if M <= 1:
        return n

    return max(1, n - math.ceil(math.log2(M)) + 1)


def hamming_bound_max_distance(n: int, M: int) -> int:
    """
    Calculate maximum distance using Hamming (sphere-packing) bound.

    Hamming bound: M · V(n, ⌊(d-1)/2⌋) ≤ 2ⁿ

    We find the largest d where this inequality holds.

    Args:
        n: Bit width
        M: Number of codewords

    Returns:
        Maximum minimum distance by Hamming bound
    """
    if M <= 1:
        return n

    max_total = 2 ** n

    # Binary search for largest d
    for d in range(n, 0, -1):
        t = (d - 1) // 2
        volume = hamming_sphere_volume(n, t)

        if M * volume <= max_total:
            return d

    return 1


def plotkin_bound_max_codewords(n: int, d: int) -> int:
    """
    Calculate maximum number of codewords for given distance using Plotkin bound.

    Plotkin bound:
    - If 2d > n and d even: M ≤ 2d/(2d - n)
    - If 2d > n and d odd:  M ≤ (2d+1)/(2d+1 - n)
    - If 2d ≤ n: M ≤ 2^(n - 2⌊d/2⌋ + 1)

    Args:
        n: Bit width
        d: Minimum distance

    Returns:
        Maximum number of codewords
    """
    if d <= 0:
        return 2 ** n

    if 2 * d > n:
        if d % 2 == 0:
            # d is even
            if 2 * d == n:
                return 4 * d
            return (2 * d) // (2 * d - n)
        else:
            # d is odd
            if 2 * d + 1 == n:
                return 4 * d + 2
            return (2 * d + 1) // (2 * d + 1 - n)
    else:
        # 2d ≤ n
        return 2 ** (n - 2 * (d // 2) + 1)


def plotkin_bound_max_distance(n: int, M: int) -> int:
    """
    Calculate maximum distance using Plotkin bound (inverse).

    Find the largest d where Plotkin bound allows M or more codewords.

    Args:
        n: Bit width
        M: Number of codewords

    Returns:
        Maximum minimum distance by Plotkin bound
    """
    if M <= 1:
        return n

    # Binary search for largest d where we can have M codewords
    for d in range(n, 0, -1):
        max_codewords = plotkin_bound_max_codewords(n, d)
        if max_codewords >= M:
            return d

    return 1


def calculate_theoretical_max_distance(n: int, M: int) -> Tuple[int, str]:
    """
    Calculate theoretical maximum minimum distance using various bounds.

    Returns the tightest (most restrictive) bound.

    Args:
        n: Bit width
        M: Number of codewords

    Returns:
        Tuple of (max_distance, bound_name)
    """
    singleton = singleton_bound_max_distance(n, M)
    hamming = hamming_bound_max_distance(n, M)
    plotkin = plotkin_bound_max_distance(n, M)

    # Return the tightest bound (minimum)
    bounds = [
        (singleton, "Singleton"),
        (hamming, "Hamming"),
        (plotkin, "Plotkin")
    ]

    # Sort by distance (ascending) to get tightest bound
    bounds.sort(key=lambda x: x[0])

    return bounds[0]


def print_theoretical_bounds(n: int, M: int):
    """
    Print theoretical bounds for given parameters.

    Args:
        n: Bit width
        M: Number of codewords
    """
    singleton = singleton_bound_max_distance(n, M)
    hamming = hamming_bound_max_distance(n, M)
    plotkin = plotkin_bound_max_distance(n, M)

    print(f"\n{'='*70}")
    print("Theoretical Maximum Minimum Distance Bounds:")
    print(f"{'='*70}")
    print(f"  Singleton bound: d ≤ {singleton}")
    print(f"  Hamming bound:   d ≤ {hamming}")
    print(f"  Plotkin bound:   d ≤ {plotkin}")
    print(f"{'='*70}")

    max_dist, bound_name = calculate_theoretical_max_distance(n, M)
    print(f"Tightest bound: {bound_name} (d ≤ {max_dist})")
    print(f"{'='*70}\n")


# =============================================================================
# Random Number Generation
# =============================================================================

def generate_random_constant(bit_width: int, rng: Union[secrets.SystemRandom, random.Random]) -> int:
    """
    Generate a cryptographically secure random constant.

    Args:
        bit_width: Number of bits
        rng: Random number generator (secure or seeded)

    Returns:
        Random constant within bit_width
    """
    max_val = (1 << bit_width) - 1
    return rng.randint(0, max_val)


def generate_balanced_constant(bit_width: int, rng: Union[secrets.SystemRandom, random.Random],
                               check_weak: bool = True) -> int:
    """
    Generate a constant with roughly balanced bit count (Hamming weight ≈ n/2).
    This is better for security as it avoids degenerate patterns.

    Args:
        bit_width: Number of bits
        rng: Random number generator
        check_weak: Whether to reject weak patterns

    Returns:
        Balanced random constant without weak patterns
    """
    target_ones = bit_width // 2
    tolerance = bit_width // 4

    for _ in range(1000):  # Try up to 1000 times
        candidate = generate_random_constant(bit_width, rng)
        ones_count = bin(candidate).count('1')

        # Check if balanced
        if abs(ones_count - target_ones) > tolerance:
            continue

        # Check for weak patterns if requested
        if check_weak:
            is_weak, _ = is_weak_pattern(candidate, bit_width)
            if is_weak:
                continue

        return candidate

    # Fallback: just return random (without weak check)
    return generate_random_constant(bit_width, rng)


def find_best_candidate(existing: List[int], bit_width: int,
                        min_required_distance: int,
                        candidates_per_round: int,
                        rng: Union[secrets.SystemRandom, random.Random],
                        check_weak: bool = True) -> Optional[int]:
    """
    Find the best candidate constant that maximizes minimum distance.

    Args:
        existing: List of existing constants
        bit_width: Number of bits
        min_required_distance: Minimum required distance
        candidates_per_round: Number of candidates to test
        rng: Random number generator
        check_weak: Whether to reject weak patterns

    Returns:
        Best candidate or None if none meets requirements
    """
    best_candidate = None
    best_min_distance = 0

    for _ in range(candidates_per_round):
        candidate = generate_balanced_constant(bit_width, rng, check_weak=check_weak)

        # Skip if duplicate
        if candidate in existing:
            continue

        # Calculate minimum distance to existing constants
        if existing:
            min_dist = min(hamming_distance(candidate, c) for c in existing)
        else:
            min_dist = bit_width  # First constant, use max possible

        # Check if meets minimum requirement
        if min_dist >= min_required_distance:
            if min_dist > best_min_distance:
                best_candidate = candidate
                best_min_distance = min_dist

    return best_candidate


def generate_constants(bit_width: int,
                      num_constants: int,
                      min_required_distance: int,
                      max_attempts: int = 100,
                      candidates_per_round: int = 1000,
                      seed: Optional[int] = None,
                      check_weak: bool = True) -> GenerationResult:
    """
    Generate a set of constants with specified minimum Hamming distance.

    Args:
        bit_width: Bit width of constants (8-64)
        num_constants: Number of constants to generate
        min_required_distance: Minimum required Hamming distance
        max_attempts: Maximum number of generation attempts
        candidates_per_round: Number of candidates to test per round
        seed: Optional random seed for reproducibility
        check_weak: Whether to reject weak patterns (default: True)

    Returns:
        GenerationResult with constants and statistics
    """
    # Use seeded RNG if seed provided, otherwise use cryptographically secure RNG
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = secrets.SystemRandom()

    best_result = None
    best_achieved_distance = 0

    for attempt in range(max_attempts):
        constants = []

        # Generate first constant
        constants.append(generate_balanced_constant(bit_width, rng, check_weak=check_weak))

        # Greedily add remaining constants
        success = True
        for _ in range(num_constants - 1):
            candidate = find_best_candidate(
                constants, bit_width, min_required_distance,
                candidates_per_round, rng, check_weak=check_weak
            )

            if candidate is None:
                success = False
                break

            constants.append(candidate)

        # Check if we succeeded
        if success and len(constants) == num_constants:
            min_dist, max_dist, avg_dist = calculate_statistics(constants)

            if min_dist >= min_required_distance:
                return GenerationResult(
                    constants=constants,
                    min_distance=min_dist,
                    max_distance=max_dist,
                    avg_distance=avg_dist,
                    success=True
                )

        # Track best attempt even if failed
        if constants:
            current_min = calculate_min_distance(constants)
            if current_min > best_achieved_distance:
                best_achieved_distance = current_min
                min_dist, max_dist, avg_dist = calculate_statistics(constants)
                best_result = GenerationResult(
                    constants=constants,
                    min_distance=min_dist,
                    max_distance=max_dist,
                    avg_distance=avg_dist,
                    success=False
                )

    # Failed to meet requirements
    return best_result or GenerationResult(
        constants=[],
        min_distance=0,
        max_distance=0,
        avg_distance=0.0,
        success=False
    )


def auto_discover_max_distance(bit_width: int, num_constants: int,
                              max_attempts: int = 100,
                              candidates_per_round: int = 1000,
                              seed: Optional[int] = None,
                              check_weak: bool = True) -> Tuple[int, GenerationResult]:
    """
    Auto-discover the maximum achievable minimum distance.

    Starts from theoretical maximum and works down until successful generation.

    Args:
        bit_width: Bit width of constants
        num_constants: Number of constants to generate
        max_attempts: Maximum attempts per distance value
        candidates_per_round: Candidates to test per round
        seed: Optional random seed
        check_weak: Whether to reject weak patterns

    Returns:
        Tuple of (achieved_distance, generation_result)
    """
    # Get theoretical maximum as starting point
    theoretical_max, bound_name = calculate_theoretical_max_distance(bit_width, num_constants)

    print(f"Auto-discovery mode: Theoretical maximum is d ≤ {theoretical_max} ({bound_name} bound)")
    print(f"Searching for maximum achievable distance...\n")

    # Try from theoretical max down to 1
    for target_distance in range(theoretical_max, 0, -1):
        print(f"Trying d = {target_distance}... ", end='', flush=True)

        result = generate_constants(
            bit_width=bit_width,
            num_constants=num_constants,
            min_required_distance=target_distance,
            max_attempts=max_attempts,
            candidates_per_round=candidates_per_round,
            seed=seed,
            check_weak=check_weak
        )

        if result.success:
            print(f"✓ SUCCESS (achieved d = {result.min_distance})")
            return result.min_distance, result
        else:
            if result.constants:
                print(f"✗ Failed (best: d = {result.min_distance})")
            else:
                print(f"✗ Failed")

    # Shouldn't reach here, but handle gracefully
    print("\nWARNING: Could not generate even with d=1")
    return 0, GenerationResult([], 0, 0, 0.0, False)


def validate_parameters(bit_width: int, num_constants: int,
                       min_distance: Optional[int]) -> Tuple[bool, Optional[str]]:
    """
    Validate generation parameters for obvious impossibilities.

    Args:
        bit_width: Bit width of constants
        num_constants: Number of constants to generate
        min_distance: Minimum required distance

    Returns:
        Tuple of (valid, error_message)
    """
    # Check bit width range
    if bit_width < 8 or bit_width > 64:
        return False, f"Bit width must be between 8 and 64 (got {bit_width})"

    # Check minimum distance bounds (only if specified)
    if min_distance is not None:
        if min_distance < 1:
            return False, f"Minimum distance must be at least 1 (got {min_distance})"

        if min_distance > bit_width:
            return False, f"Minimum distance ({min_distance}) cannot exceed bit width ({bit_width})"

    # Check number of constants
    if num_constants < 1:
        return False, f"Must generate at least 1 constant (got {num_constants})"

    max_possible = 1 << bit_width
    if num_constants > max_possible:
        return False, f"Cannot generate {num_constants} unique {bit_width}-bit constants (max possible: {max_possible})"

    # Use theoretical bounds to check if parameters are likely impossible (only if min_distance specified)
    if min_distance is not None:
        max_dist, bound_name = calculate_theoretical_max_distance(bit_width, num_constants)

        if min_distance > max_dist:
            return False, (f"Parameters exceed theoretical limits: Requested min distance {min_distance} "
                          f"but {bound_name} bound gives maximum d ≤ {max_dist} for "
                          f"{num_constants} {bit_width}-bit constants")

    return True, None


def format_c_enum(constants: List[int], bit_width: int,
                 enum_name: str = "SecureConstants",
                 prefix: str = "SECURE_CONST") -> str:
    """
    Format constants as C enumeration.

    Args:
        constants: List of constants
        bit_width: Bit width of constants
        enum_name: Name of the enum
        prefix: Prefix for constant names (default: SECURE_CONST)

    Returns:
        C enum definition as string
    """
    hex_width = (bit_width + 3) // 4

    # Determine appropriate type based on bit width
    if bit_width <= 8:
        type_suffix = "U"
        comment_type = "uint8_t"
    elif bit_width <= 16:
        type_suffix = "U"
        comment_type = "uint16_t"
    elif bit_width <= 32:
        type_suffix = "UL"
        comment_type = "uint32_t"
    else:
        type_suffix = "ULL"
        comment_type = "uint64_t"

    lines = []
    lines.append(f"/* Auto-generated secure constants ({bit_width}-bit, {len(constants)} values) */")
    lines.append(f"/* Minimum Hamming distance: {calculate_min_distance(constants)} */")
    lines.append(f"/* Type: {comment_type} */")
    lines.append("")
    lines.append(f"enum {enum_name} {{")

    for i, const in enumerate(constants):
        weight = bin(const).count('1')
        lines.append(f"    {prefix}_{i:02d} = 0x{const:0{hex_width}X}{type_suffix},  /* weight: {weight} */")

    lines.append("};")

    return "\n".join(lines)


def format_c_defines(constants: List[int], bit_width: int,
                    prefix: str = "SECURE_CONST") -> str:
    """
    Format constants as C #define statements.

    Args:
        constants: List of constants
        bit_width: Bit width of constants
        prefix: Prefix for define names (default: SECURE_CONST)

    Returns:
        C #define statements as string
    """
    hex_width = (bit_width + 3) // 4

    # Determine appropriate type suffix
    if bit_width <= 8:
        type_suffix = "U"
        comment_type = "uint8_t"
    elif bit_width <= 16:
        type_suffix = "U"
        comment_type = "uint16_t"
    elif bit_width <= 32:
        type_suffix = "UL"
        comment_type = "uint32_t"
    else:
        type_suffix = "ULL"
        comment_type = "uint64_t"

    lines = []
    lines.append(f"/* Auto-generated secure constants ({bit_width}-bit, {len(constants)} values) */")
    lines.append(f"/* Minimum Hamming distance: {calculate_min_distance(constants)} */")
    lines.append(f"/* Type: {comment_type} */")
    lines.append("")

    for i, const in enumerate(constants):
        weight = bin(const).count('1')
        lines.append(f"#define {prefix}_{i:02d}  0x{const:0{hex_width}X}{type_suffix}  /* weight: {weight} */")

    return "\n".join(lines)


def print_results(result: GenerationResult, bit_width: int,
                 num_constants: int, min_required_distance: Optional[int],
                 show_bounds: bool = False, auto_mode: bool = False,
                 output_format: str = "default", prefix: str = "SECURE_CONST"):
    """
    Print generation results in a formatted way.

    Args:
        result: Generation result
        bit_width: Bit width used
        num_constants: Number of constants requested
        min_required_distance: Minimum required distance (None if auto-discovery)
        show_bounds: Whether to show theoretical bounds
        auto_mode: Whether this was auto-discovery mode
        output_format: Output format ("default", "c-enum", "c-define")
        prefix: Prefix for C constant names
    """
    if not result.success:
        if min_required_distance is not None:
            print(f"\nERROR: Could not generate {num_constants} constants with minimum distance {min_required_distance}")
        else:
            print(f"\nERROR: Could not generate {num_constants} constants")

        if result.constants:
            print(f"Best achieved: {result.min_distance} with {len(result.constants)} constants")

        # Show theoretical bounds to help user understand limits
        max_dist, bound_name = calculate_theoretical_max_distance(bit_width, num_constants)
        print(f"\nTheoretical limit: {bound_name} bound gives maximum d ≤ {max_dist}")

        print(f"\nSuggestions:")
        print(f"  - Reduce minimum distance requirement (try d ≤ {max_dist})")
        print(f"  - Reduce number of constants")
        print(f"  - Increase bit width")
        return

    # Always show detailed output first
    print(f"\n{'='*70}")
    print(f"Generated {num_constants} constants ({bit_width}-bit)")
    print(f"Minimum Hamming distance: {result.min_distance}", end='')
    if auto_mode:
        # Show theoretical comparison
        theoretical_max, bound_name = calculate_theoretical_max_distance(bit_width, num_constants)
        efficiency = (result.min_distance / theoretical_max * 100) if theoretical_max > 0 else 0
        print(f" (auto-discovered, {efficiency:.0f}% of theoretical max)")
    else:
        print()
    print(f"{'='*70}\n")

    # Print constants
    print("Constants:")
    hex_width = (bit_width + 3) // 4  # Number of hex digits needed
    for i, const in enumerate(result.constants):
        print(f"  [{i:2d}]  0x{const:0{hex_width}X}  (weight: {bin(const).count('1')})")

    # Print statistics
    print(f"\n{'='*70}")
    print("Statistics:")
    print(f"  Minimum distance: {result.min_distance}")
    print(f"  Maximum distance: {result.max_distance}")
    print(f"  Average distance: {result.avg_distance:.2f}")
    print(f"{'='*70}\n")

    # Check for weak patterns
    weak_patterns = check_set_for_weak_patterns(result.constants, bit_width)
    if weak_patterns:
        print(f"{'='*70}")
        print(f"WARNING: Weak patterns detected ({len(weak_patterns)} constants)")
        print(f"{'='*70}")
        for idx, value, reason in weak_patterns:
            hex_width = (bit_width + 3) // 4
            print(f"  [{idx:2d}]  0x{value:0{hex_width}X}  - {reason}")
        print(f"{'='*70}\n")

    # Print theoretical bounds if requested
    if show_bounds:
        print_theoretical_bounds(bit_width, num_constants)

    # Print distance matrix
    print("Hamming Distance Matrix:")
    print("      ", end="")
    for i in range(len(result.constants)):
        print(f"[{i:2d}]", end=" ")
    print()

    matrix = calculate_distance_matrix(result.constants)
    for i in range(len(result.constants)):
        print(f"[{i:2d}]  ", end="")
        for j in range(len(result.constants)):
            if i == j:
                print("  - ", end=" ")
            else:
                print(f"{matrix[i][j]:3d}", end=" ")
        print()
    print()

    # Add C format output at the end if requested
    if output_format == "c-enum":
        print(f"{'='*70}")
        print("C Enumeration Format:")
        print(f"{'='*70}\n")
        print(format_c_enum(result.constants, bit_width, prefix=prefix))
        print()
    elif output_format == "c-define":
        print(f"{'='*70}")
        print("C #define Format:")
        print(f"{'='*70}\n")
        print(format_c_defines(result.constants, bit_width, prefix=prefix))
        print()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Generate secure constants with maximum Hamming distance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Auto-discover maximum distance for 10 32-bit constants:
    %(prog)s --bits 32 --count 10

  Generate 10 32-bit constants with minimum distance 16:
    %(prog)s --bits 32 --count 10 --min-distance 16

  Generate 5 16-bit constants with minimum distance 8:
    %(prog)s -b 16 -c 5 -m 8

  Show theoretical bounds with auto-discovery:
    %(prog)s -b 32 -c 10 --show-bounds

  Output in C enum format:
    %(prog)s -b 32 -c 10 --format c-enum

  Output in C #define format:
    %(prog)s -b 32 -c 10 -m 16 --format c-define
        """
    )

    parser.add_argument('-b', '--bits', type=int, required=True,
                       help='Bit width of constants (8-64)')
    parser.add_argument('-c', '--count', type=int, required=True,
                       help='Number of constants to generate')
    parser.add_argument('-m', '--min-distance', type=int, default=None,
                       help='Minimum required Hamming distance (optional: auto-discovers maximum if not specified)')
    parser.add_argument('-a', '--attempts', type=int, default=100,
                       help='Maximum generation attempts (default: 100)')
    parser.add_argument('--candidates', type=int, default=1000,
                       help='Candidates to test per round (default: 1000)')
    parser.add_argument('-s', '--seed', type=int, default=None,
                       help='Random seed for reproducibility (optional)')
    parser.add_argument('--show-bounds', action='store_true',
                       help='Show theoretical bounds (Singleton, Hamming, Plotkin)')
    parser.add_argument('-f', '--format', dest='output_format',
                       choices=['default', 'c-enum', 'c-define'],
                       default='default',
                       help='Output format: default (detailed), c-enum (C enumeration), c-define (C #define)')
    parser.add_argument('-p', '--prefix', type=str, default='SECURE_CONST',
                       help='Prefix for C constant names (default: SECURE_CONST)')

    args = parser.parse_args()

    # Validate parameters
    valid, error_msg = validate_parameters(args.bits, args.count, args.min_distance)
    if not valid:
        print(f"ERROR: {error_msg}", file=sys.stderr)
        return 2

    # Auto-discovery mode if min_distance not specified
    if args.min_distance is None:
        print(f"Generating {args.count} {args.bits}-bit constants (auto-discovering maximum distance)...")
        print(f"(Testing up to {args.attempts} attempts with {args.candidates} candidates per round)\n")

        achieved_distance, result = auto_discover_max_distance(
            bit_width=args.bits,
            num_constants=args.count,
            max_attempts=args.attempts,
            candidates_per_round=args.candidates,
            seed=args.seed
        )

        if result.success:
            print()  # Blank line before results
            print_results(result, args.bits, args.count, achieved_distance, args.show_bounds, auto_mode=True, output_format=args.output_format, prefix=args.prefix)
            return 0
        else:
            print(f"\nERROR: Failed to generate constants even with minimum distance requirements")
            return 1
    else:
        # Manual mode with specified min_distance
        print(f"Generating {args.count} {args.bits}-bit constants with min distance {args.min_distance}...")
        print(f"(Testing up to {args.attempts} attempts with {args.candidates} candidates per round)")

        result = generate_constants(
            bit_width=args.bits,
            num_constants=args.count,
            min_required_distance=args.min_distance,
            max_attempts=args.attempts,
            candidates_per_round=args.candidates,
            seed=args.seed
        )

        # Print results
        print_results(result, args.bits, args.count, args.min_distance, args.show_bounds, auto_mode=False, output_format=args.output_format, prefix=args.prefix)

        # Return appropriate exit code
        return 0 if result.success else 1


if __name__ == '__main__':
    sys.exit(main())
