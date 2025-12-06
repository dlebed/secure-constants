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


def check_for_complements(constants: List[int], bit_width: int) -> List[Tuple[int, int]]:
    """
    Check if any constants are bitwise complements of each other.

    This is a security vulnerability because a single stuck-at fault affecting
    all bits (e.g., voltage glitch on bus) can transform A into ~A.

    Args:
        constants: List of constants
        bit_width: Bit width of constants

    Returns:
        List of (index_i, index_j) pairs where constants[i] == ~constants[j]
    """
    complement_pairs = []
    max_val = (1 << bit_width) - 1

    for i in range(len(constants)):
        for j in range(i + 1, len(constants)):
            # Calculate bitwise complement within bit_width
            complement_i = constants[i] ^ max_val

            if complement_i == constants[j]:
                complement_pairs.append((i, j))

    return complement_pairs


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
# Bit Difference Clustering Analysis
# =============================================================================

def analyze_bit_clustering(value1: int, value2: int, bit_width: int) -> dict:
    """
    Analyze spatial distribution of bit differences between two values.

    Detects clustering of bit differences which could make fault injection
    attacks easier by targeting specific regions (bytes, nibbles, power rails).

    Args:
        value1: First constant
        value2: Second constant
        bit_width: Bit width of constants

    Returns:
        Dictionary with clustering metrics:
        - max_cluster_size: Longest run of consecutive differing bits
        - max_gap: Largest gap between differing bits
        - byte_coverage: Fraction of bytes that contain at least one difference (0.0-1.0)
        - distribution_variance: Variance of differences across bytes (lower = more even)
        - differing_bits: Total Hamming distance
        - diff_positions: List of bit positions that differ
    """
    xor = value1 ^ value2

    # Get positions of differing bits (LSB = position 0)
    diff_positions = [i for i in range(bit_width) if (xor >> i) & 1]

    if len(diff_positions) == 0:
        return {
            'max_cluster_size': 0,
            'max_gap': 0,
            'byte_coverage': 0.0,
            'distribution_variance': 0.0,
            'differing_bits': 0,
            'diff_positions': []
        }

    if len(diff_positions) == 1:
        num_bytes = (bit_width + 7) // 8
        return {
            'max_cluster_size': 1,
            'max_gap': 0,
            'byte_coverage': 1.0 / num_bytes,
            'distribution_variance': 0.0,
            'differing_bits': 1,
            'diff_positions': diff_positions
        }

    # Calculate gaps between consecutive differing bits
    gaps = [diff_positions[i+1] - diff_positions[i]
            for i in range(len(diff_positions)-1)]

    # Find maximum run of consecutive bits (cluster size)
    max_cluster = 1
    current_cluster = 1
    for i in range(1, len(diff_positions)):
        if diff_positions[i] == diff_positions[i-1] + 1:
            current_cluster += 1
            max_cluster = max(max_cluster, current_cluster)
        else:
            current_cluster = 1

    # Byte-level distribution analysis
    num_bytes = (bit_width + 7) // 8
    bytes_with_diffs = set()
    byte_counts = [0] * num_bytes

    for pos in diff_positions:
        byte_idx = pos // 8
        bytes_with_diffs.add(byte_idx)
        byte_counts[byte_idx] += 1

    byte_coverage = len(bytes_with_diffs) / num_bytes

    # Calculate variance (measure of evenness across bytes)
    # Lower variance = more evenly distributed
    mean_per_byte = len(diff_positions) / num_bytes
    variance = sum((c - mean_per_byte)**2 for c in byte_counts) / num_bytes

    return {
        'max_cluster_size': max_cluster,
        'max_gap': max(gaps),
        'byte_coverage': byte_coverage,
        'distribution_variance': variance,
        'differing_bits': len(diff_positions),
        'diff_positions': diff_positions
    }


def calculate_distribution_score(clustering_info: dict, bit_width: int) -> float:
    """
    Calculate quality score (0-100) for bit difference distribution.

    Higher scores indicate better-distributed differences, which provide
    better security against localized fault injection attacks.

    Scoring factors:
    - Penalizes large clusters of consecutive differences
    - Rewards broad byte coverage
    - Penalizes uneven distribution across bytes

    Args:
        clustering_info: Output from analyze_bit_clustering()
        bit_width: Bit width of constants

    Returns:
        Quality score from 0 (worst clustering) to 100 (perfect distribution)
    """
    hamming_dist = clustering_info['differing_bits']
    if hamming_dist == 0:
        return 0.0

    # Start with perfect score
    score = 100.0

    # Penalize large clusters (consecutive runs)
    # A cluster of size k out of d total differences is bad
    cluster_ratio = clustering_info['max_cluster_size'] / hamming_dist
    cluster_penalty = cluster_ratio * 40.0  # Up to -40 points
    score -= cluster_penalty

    # Reward good byte coverage
    # Perfect coverage (all bytes have diffs) = no penalty
    # Poor coverage = penalty
    coverage_penalty = (1.0 - clustering_info['byte_coverage']) * 30.0  # Up to -30 points
    score -= coverage_penalty

    # Penalize high variance (uneven distribution)
    # Normalize variance by hamming distance
    normalized_variance = clustering_info['distribution_variance'] / max(hamming_dist, 1)
    variance_penalty = min(normalized_variance * 20.0, 30.0)  # Up to -30 points
    score -= variance_penalty

    return max(0.0, min(100.0, score))


def calculate_bit_difference_histogram(constants: List[int], bit_width: int) -> dict:
    """
    Calculate histogram of bit differences across all constant pairs.

    Analyzes spatial distribution of bit differences to identify hot/cold spots
    that could be exploited by localized fault injection attacks.

    Args:
        constants: List of constants
        bit_width: Bit width of constants

    Returns:
        Dictionary with:
        - bit_position_counts: Array of difference counts per bit position
        - byte_counts: Array of difference counts per byte
        - hamming_distance_histogram: Count of pairs for each Hamming distance
        - total_pairs: Total number of pairs analyzed
    """
    num_bytes = (bit_width + 7) // 8
    bit_position_counts = [0] * bit_width
    byte_counts = [0] * num_bytes
    hamming_distance_histogram = {}
    total_pairs = 0

    for i in range(len(constants)):
        for j in range(i + 1, len(constants)):
            total_pairs += 1
            xor = constants[i] ^ constants[j]
            hamming_dist = bin(xor).count('1')

            # Update Hamming distance histogram
            hamming_distance_histogram[hamming_dist] = hamming_distance_histogram.get(hamming_dist, 0) + 1

            # Count differences per bit position
            for bit_pos in range(bit_width):
                if (xor >> bit_pos) & 1:
                    bit_position_counts[bit_pos] += 1

            # Count differences per byte
            for byte_idx in range(num_bytes):
                byte_mask = 0xFF << (byte_idx * 8)
                if xor & byte_mask:
                    byte_counts[byte_idx] += 1

    return {
        'bit_position_counts': bit_position_counts,
        'byte_counts': byte_counts,
        'hamming_distance_histogram': hamming_distance_histogram,
        'total_pairs': total_pairs
    }


def visualize_hamming_distance_histogram(histogram: dict, width: int = 50) -> str:
    """
    Create ASCII histogram of Hamming distances.

    Args:
        histogram: Hamming distance histogram from calculate_bit_difference_histogram
        width: Width of histogram bars in characters

    Returns:
        Multi-line string with ASCII histogram
    """
    if not histogram:
        return "No data to display"

    lines = []
    lines.append("Hamming Distance Distribution:")
    lines.append("")

    hamming_hist = histogram['hamming_distance_histogram']
    total_pairs = histogram['total_pairs']

    if not hamming_hist:
        return "No pairs analyzed"

    # Find max count for scaling
    max_count = max(hamming_hist.values())

    # Sort by distance
    for distance in sorted(hamming_hist.keys()):
        count = hamming_hist[distance]
        percentage = (count / total_pairs * 100) if total_pairs > 0 else 0

        # Calculate bar length
        bar_length = int((count / max_count * width)) if max_count > 0 else 0

        # Create bar
        bar = "█" * bar_length

        lines.append(f"  d={distance:2d} │{bar:<{width}} │ {count:3d} pairs ({percentage:5.1f}%)")

    lines.append("")
    return "\n".join(lines)


def visualize_bit_position_heatmap(histogram: dict, bit_width: int, width: int = 64) -> str:
    """
    Create ASCII heatmap showing which bit positions differ most frequently.

    This helps identify vulnerable bit positions that differ frequently,
    which could be targeted by position-specific fault injection attacks.

    Args:
        histogram: Bit difference histogram from calculate_bit_difference_histogram
        bit_width: Bit width of constants
        width: Maximum width for display

    Returns:
        Multi-line string with ASCII heatmap
    """
    lines = []
    lines.append("Bit Position Difference Frequency (hot spots = frequently different):")
    lines.append("")

    bit_counts = histogram['bit_position_counts']
    total_pairs = histogram['total_pairs']

    if not bit_counts or total_pairs == 0:
        return "No data to display"

    max_count = max(bit_counts) if bit_counts else 1

    # ASCII characters for different intensity levels
    intensity_chars = [' ', '░', '▒', '▓', '█']

    # Group by bytes for readability
    num_bytes = (bit_width + 7) // 8

    # Bit position labels (show every 8th bit)
    lines.append("  Bit:  " + "".join(f"{i*8:^8}" for i in range(num_bytes)))

    # Draw heatmap row
    heatmap_line = "        "
    for byte_idx in range(num_bytes):
        for bit_in_byte in range(8):
            bit_pos = byte_idx * 8 + bit_in_byte
            if bit_pos < bit_width:
                count = bit_counts[bit_pos]
                # Map count to intensity (0-100%)
                intensity = (count / max_count) if max_count > 0 else 0
                char_idx = min(int(intensity * len(intensity_chars)), len(intensity_chars) - 1)
                heatmap_line += intensity_chars[char_idx]
            else:
                heatmap_line += ' '
        heatmap_line += ' '

    lines.append(heatmap_line)

    # Byte labels
    lines.append("  Byte: " + "".join(f"{i:^8}" for i in range(num_bytes)))
    lines.append("")

    # Legend
    lines.append(f"  Legend: {intensity_chars[0]}=0% {intensity_chars[1]}=25% {intensity_chars[2]}=50% {intensity_chars[3]}=75% {intensity_chars[4]}=100%")
    lines.append("")

    # Show statistics per byte
    lines.append("  Byte-level difference counts:")
    num_bytes = (bit_width + 7) // 8
    for byte_idx in range(num_bytes):
        byte_diff_sum = sum(bit_counts[byte_idx * 8 + i] for i in range(8) if byte_idx * 8 + i < bit_width)
        avg_per_bit = byte_diff_sum / 8 if byte_diff_sum > 0 else 0
        percentage = (byte_diff_sum / (total_pairs * 8) * 100) if total_pairs > 0 else 0

        # Create mini bar
        bar_width = 20
        bar_length = int((byte_diff_sum / (max_count * 8) * bar_width)) if max_count > 0 else 0
        bar = "▓" * bar_length + "░" * (bar_width - bar_length)

        lines.append(f"    Byte {byte_idx}: │{bar}│ {byte_diff_sum:4d} diffs ({percentage:5.1f}%)")

    lines.append("")

    # Analysis
    min_byte_sum = min(sum(bit_counts[byte_idx * 8 + i] for i in range(8) if byte_idx * 8 + i < bit_width)
                       for byte_idx in range(num_bytes))
    max_byte_sum = max(sum(bit_counts[byte_idx * 8 + i] for i in range(8) if byte_idx * 8 + i < bit_width)
                       for byte_idx in range(num_bytes))

    if max_byte_sum > 0:
        imbalance = (max_byte_sum - min_byte_sum) / max_byte_sum * 100
        if imbalance > 30:
            lines.append(f"  ⚠ Warning: Byte imbalance detected ({imbalance:.1f}%)")
            lines.append(f"    Differences are not evenly distributed across bytes.")
        else:
            lines.append(f"  ✓ Good: Differences are well-distributed across bytes ({imbalance:.1f}% imbalance)")

    lines.append("")
    return "\n".join(lines)


def visualize_bit_differences(value1: int, value2: int, bit_width: int,
                               label1: str = "A", label2: str = "B") -> str:
    """
    Generate ASCII visualization of bit difference positions.

    Shows where bits differ between two values, grouped by bytes for readability.
    Useful for identifying clustering patterns visually.

    Args:
        value1: First constant
        value2: Second constant
        bit_width: Bit width of constants
        label1: Label for first value
        label2: Label for second value

    Returns:
        Multi-line string with visualization
    """
    xor = value1 ^ value2
    num_bytes = (bit_width + 7) // 8

    lines = []

    # Hex values
    hex_width = (bit_width + 3) // 4
    lines.append(f"  {label1}: 0x{value1:0{hex_width}X}")
    lines.append(f"  {label2}: 0x{value2:0{hex_width}X}")
    lines.append(f"  XOR: 0x{xor:0{hex_width}X}")
    lines.append("")

    # Bit difference map (X = different, . = same)
    lines.append("  Bit difference map (X = different, . = same):")
    line = "  "

    # Print bytes from high to low (left to right)
    for byte_idx in range(num_bytes - 1, -1, -1):
        for bit_idx in range(7, -1, -1):
            pos = byte_idx * 8 + bit_idx
            if pos < bit_width:
                if (xor >> pos) & 1:
                    line += "X"
                else:
                    line += "."
        line += " "

    lines.append(line)

    # Byte labels
    byte_line = "  Byte: "
    for byte_idx in range(num_bytes - 1, -1, -1):
        byte_line += f"{byte_idx:^8} "
    lines.append(byte_line)

    return "\n".join(lines)


def print_clustering_analysis(constants: List[int], bit_width: int,
                              show_details: bool = False, threshold: float = 60.0):
    """
    Print clustering analysis for all pairs of generated constants.

    Identifies pairs with poor bit difference distribution that may be
    vulnerable to localized fault injection attacks.

    Args:
        constants: List of generated constants
        bit_width: Bit width of constants
        show_details: If True, show detailed analysis of worst pairs
        threshold: Score threshold below which to flag pairs (0-100)
    """
    if len(constants) < 2:
        return

    print("\n" + "="*70)
    print("Bit Difference Distribution Analysis:")
    print("="*70)

    # Analyze all pairs
    pair_analyses = []
    total_pairs = 0

    for i in range(len(constants)):
        for j in range(i+1, len(constants)):
            total_pairs += 1
            cluster_info = analyze_bit_clustering(constants[i], constants[j], bit_width)
            score = calculate_distribution_score(cluster_info, bit_width)
            pair_analyses.append((i, j, score, cluster_info))

    # Sort by score (worst first)
    pair_analyses.sort(key=lambda x: x[2])

    # Count pairs by quality
    excellent = sum(1 for _, _, score, _ in pair_analyses if score >= 80)
    good = sum(1 for _, _, score, _ in pair_analyses if 60 <= score < 80)
    fair = sum(1 for _, _, score, _ in pair_analyses if 40 <= score < 60)
    poor = sum(1 for _, _, score, _ in pair_analyses if score < 40)

    # Calculate statistics
    avg_score = sum(score for _, _, score, _ in pair_analyses) / total_pairs
    avg_cluster = sum(info['max_cluster_size'] for _, _, _, info in pair_analyses) / total_pairs
    avg_coverage = sum(info['byte_coverage'] for _, _, _, info in pair_analyses) / total_pairs

    print(f"\nOverall Statistics ({total_pairs} pairs analyzed):")
    print(f"  Average distribution score: {avg_score:.1f}/100")
    print(f"  Average max cluster size: {avg_cluster:.1f} bits")
    print(f"  Average byte coverage: {avg_coverage*100:.1f}%")
    print(f"\nQuality Distribution:")
    print(f"  Excellent (≥80): {excellent:3d} pairs ({excellent*100/total_pairs:.1f}%)")
    print(f"  Good (60-79):    {good:3d} pairs ({good*100/total_pairs:.1f}%)")
    print(f"  Fair (40-59):    {fair:3d} pairs ({fair*100/total_pairs:.1f}%)")
    print(f"  Poor (<40):      {poor:3d} pairs ({poor*100/total_pairs:.1f}%)")

    # Flag problematic pairs
    flagged = [p for p in pair_analyses if p[2] < threshold]

    if flagged:
        print(f"\n⚠ WARNING: {len(flagged)} pairs below quality threshold ({threshold:.0f}):")

        # Show up to 5 worst pairs
        num_to_show = min(5, len(flagged)) if not show_details else len(flagged)

        for idx, (i, j, score, info) in enumerate(flagged[:num_to_show]):
            print(f"\n  Pair #{idx+1}: [{i:2d}] vs [{j:2d}]  Score: {score:.1f}/100")
            print(f"    Hamming distance: {info['differing_bits']}")
            print(f"    Max cluster: {info['max_cluster_size']} consecutive bits")
            print(f"    Byte coverage: {info['byte_coverage']*100:.1f}%")
            print(f"    Distribution variance: {info['distribution_variance']:.2f}")

            if show_details:
                # Show visual representation
                print(visualize_bit_differences(constants[i], constants[j], bit_width,
                                               f"[{i:2d}]", f"[{j:2d}]"))

        if len(flagged) > num_to_show and not show_details:
            print(f"\n  ... and {len(flagged) - num_to_show} more pairs")
            print("  (Use --show-clustering for detailed analysis)")
    else:
        print(f"\n✓ All constant pairs have well-distributed bit differences (≥{threshold:.0f})")

    # Show best pair as example
    if pair_analyses:
        best_i, best_j, best_score, best_info = pair_analyses[-1]
        print(f"\nBest distributed pair: [{best_i:2d}] vs [{best_j:2d}]  Score: {best_score:.1f}/100")
        if show_details:
            print(visualize_bit_differences(constants[best_i], constants[best_j], bit_width,
                                           f"[{best_i:2d}]", f"[{best_j:2d}]"))


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
# Architecture-Specific Instruction Constraints
# =============================================================================

def is_riscv_single_instruction(value: int) -> bool:
    """
    Check if 32-bit value can be loaded with single RISC-V RV32I instruction.

    Single-instruction loadable values:
    - ADDI: signed 12-bit immediate range [-2048, 2047]
      As 32-bit unsigned: 0x00000000-0x000007FF, 0xFFFFF800-0xFFFFFFFF
    - LUI: upper 20 bits loaded, lower 12 bits zero (multiples of 4096)
      Values: 0x00000000, 0x00001000, 0x00002000, ..., 0xFFFFF000

    Args:
        value: 32-bit value to check (treated as unsigned)

    Returns:
        True if loadable with single RV32I instruction
    """
    # Ensure 32-bit unsigned representation
    value = value & 0xFFFFFFFF

    # ADDI range: 0 to 2047 (positive immediates)
    if value <= 0x7FF:
        return True

    # ADDI range: -2048 to -1 in two's complement (0xFFFFF800 to 0xFFFFFFFF)
    if value >= 0xFFFFF800:
        return True

    # LUI loadable: multiple of 4096 (lower 12 bits all zero)
    if (value & 0xFFF) == 0:
        return True

    return False


def expand_arm_modified_immediate(imm12: int) -> int:
    """
    Expand ARM Thumb-2 modified immediate encoding to 32-bit value.

    ARM Thumb-2 modified immediate encoding (12 bits):
    Format: i:imm3:a:bcdefgh

    Encoding rules:
    - If imm3:a = 0b0000: 0x00000000XY (where XY = 0bcdefgh)
    - If imm3:a = 0b0001: 0x00XY00XY
    - If imm3:a = 0b0010: 0xXY00XY00
    - If imm3:a = 0b0011: 0xXYXYXYXY
    - If imm3:a = 0b0100-0b1111: Rotate right (1bcdefgh << 24) by 2*imm3a bits

    Args:
        imm12: 12-bit modified immediate encoding

    Returns:
        Expanded 32-bit value

    Reference: ARM Architecture Reference Manual ARMv7-A/R
               Section A5.3.2 Modified immediate constants in Thumb instructions
    """
    # Extract fields from 12-bit encoding
    i = (imm12 >> 11) & 1
    imm3 = (imm12 >> 8) & 0x7
    a = (imm12 >> 7) & 1
    bcdefgh = imm12 & 0x7F

    # Combine imm3:a to get 4-bit mode selector
    imm3a = (imm3 << 1) | a

    # Mode 0: 0x00000000XY
    if imm3a == 0b0000:
        return bcdefgh

    # Mode 1: 0x00XY00XY
    elif imm3a == 0b0001:
        return (bcdefgh << 16) | bcdefgh

    # Mode 2: 0xXY00XY00
    elif imm3a == 0b0010:
        return (bcdefgh << 24) | (bcdefgh << 8)

    # Mode 3: 0xXYXYXYXY
    elif imm3a == 0b0011:
        return (bcdefgh << 24) | (bcdefgh << 16) | (bcdefgh << 8) | bcdefgh

    # Modes 4-15: Rotation encoding
    else:
        # Construct 8-bit value: 1bcdefgh (ensure bit 7 is set)
        imm8 = 0x80 | bcdefgh

        # Rotation amount: 2 * imm3a bits
        rotation = 2 * imm3a

        # Rotate right: shift value to be placed in bits [31:24] then rotate
        # The ARM encoding rotates the value 1bcdefgh initially placed at bits 31:24
        value = imm8 << 24
        rotated = ((value >> rotation) | (value << (32 - rotation))) & 0xFFFFFFFF

        return rotated


def is_arm_modified_immediate(value: int) -> bool:
    """
    Check if value can be encoded as ARM Thumb-2 modified immediate.

    Brute force approach: test all 4096 possible encodings.
    This is fast enough for our use case (4096 iterations).

    Args:
        value: 32-bit value to check

    Returns:
        True if value matches any modified immediate encoding
    """
    value = value & 0xFFFFFFFF

    for imm12 in range(4096):
        if expand_arm_modified_immediate(imm12) == value:
            return True

    return False


def is_arm_single_instruction(value: int) -> bool:
    """
    Check if 32-bit value can be loaded with single ARM Thumb-2 32-bit instruction.

    Single-instruction loadable values:
    - MOVW (T3 encoding): Any 16-bit immediate zero-extended (0x00000000-0x0000FFFF)
    - MOV (T2 encoding): Modified immediate patterns (rotated 8-bit values)
    - MVN: Bitwise NOT of modified immediate patterns

    Args:
        value: 32-bit value to check (treated as unsigned)

    Returns:
        True if loadable with single ARM Thumb-2 32-bit instruction
    """
    value = value & 0xFFFFFFFF

    # MOVW can load any 16-bit value (zero-extended to 32 bits)
    if value <= 0xFFFF:
        return True

    # MOV with modified immediate encoding
    if is_arm_modified_immediate(value):
        return True

    # MVN (move NOT) with modified immediate
    # MVN loads the bitwise complement of the modified immediate
    inverted = (~value) & 0xFFFFFFFF
    if is_arm_modified_immediate(inverted):
        return True

    return False


def precompute_riscv_valid_set() -> set:
    """
    Pre-compute all RISC-V RV32I single-instruction loadable 32-bit values.

    This includes:
    - ADDI range: 4,096 values ([-2048, 2047] as signed)
    - LUI range: 1,048,576 values (multiples of 4096)
    Total: ~1,052,672 unique values (0.024% of 2^32 space)

    Returns:
        Set of all valid 32-bit values
    """
    valid = set()

    # ADDI range: [-2048, 2047]
    for val in range(-2048, 2048):
        if val < 0:
            # Convert negative to 32-bit unsigned (two's complement)
            valid.add((1 << 32) + val)
        else:
            valid.add(val)

    # LUI range: multiples of 4096 (lower 12 bits zero)
    # upper_20 can be 0 to (2^20 - 1)
    for upper_20 in range(1 << 20):
        valid.add(upper_20 << 12)

    return valid


def precompute_arm_valid_set() -> set:
    """
    Pre-compute all ARM Thumb-2 single-instruction loadable 32-bit values.

    This includes:
    - MOVW range: 65,536 values (0x0000-0xFFFF)
    - MOV modified immediate: ~1,024 unique patterns
    - MVN modified immediate: ~1,024 unique patterns (bitwise NOT)
    Total: ~67,000-69,000 unique values (0.0016% of 2^32 space)

    Returns:
        Set of all valid 32-bit values
    """
    valid = set()

    # MOVW range: any 16-bit value zero-extended
    for val in range(0x10000):
        valid.add(val)

    # MOV with modified immediate: all 4096 possible encodings
    for imm12 in range(4096):
        valid.add(expand_arm_modified_immediate(imm12))

    # MVN with modified immediate: bitwise NOT of all encodings
    for imm12 in range(4096):
        value = expand_arm_modified_immediate(imm12)
        inverted = (~value) & 0xFFFFFFFF
        valid.add(inverted)

    return valid


def describe_riscv_instruction(value: int) -> str:
    """
    Return RISC-V RV32I assembly instruction for loading this value.

    Args:
        value: 32-bit value

    Returns:
        Assembly instruction string or error message
    """
    value = value & 0xFFFFFFFF

    # ADDI positive range
    if value <= 0x7FF:
        return f"addi rd, zero, {value}"

    # ADDI negative range (two's complement)
    elif value >= 0xFFFFF800:
        signed = value - (1 << 32)  # Convert to signed
        return f"addi rd, zero, {signed}"

    # LUI (multiple of 4096)
    elif (value & 0xFFF) == 0:
        upper_20 = value >> 12
        return f"lui rd, 0x{upper_20:05X}"

    else:
        return "ERROR: Not single-instruction loadable"


def describe_arm_instruction(value: int) -> str:
    """
    Return ARM Thumb-2 assembly instruction for loading this value.

    Args:
        value: 32-bit value

    Returns:
        Assembly instruction string or error message
    """
    value = value & 0xFFFFFFFF

    # MOVW (16-bit immediate)
    if value <= 0xFFFF:
        return f"movw r0, #0x{value:04X}"

    # MOV with modified immediate
    elif is_arm_modified_immediate(value):
        return f"mov r0, #0x{value:08X}"

    # MVN with modified immediate
    else:
        inverted = (~value) & 0xFFFFFFFF
        if is_arm_modified_immediate(inverted):
            return f"mvn r0, #0x{inverted:08X}"

    return "ERROR: Not single-instruction loadable"


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


def generate_riscv_candidate(rng: Union[secrets.SystemRandom, random.Random]) -> int:
    """
    Generate random 32-bit value from RISC-V RV32I single-instruction loadable set.

    Generates from:
    - ADDI range: 4,096 values (30% probability)
    - LUI range: 1,048,576 values (70% probability - larger set)

    Args:
        rng: Random number generator

    Returns:
        Random 32-bit value loadable with single RV32I instruction
    """
    # Weight by set size: LUI range is much larger
    if rng.random() < 0.7:
        # LUI: multiple of 4096 (upper 20 bits, lower 12 zero)
        upper_20 = rng.randint(0, (1 << 20) - 1)
        return upper_20 << 12
    else:
        # ADDI: signed 12-bit immediate [-2048, 2047]
        signed_val = rng.randint(-2048, 2047)
        if signed_val < 0:
            # Convert negative to 32-bit unsigned (two's complement)
            return (1 << 32) + signed_val
        return signed_val


def generate_arm_candidate(rng: Union[secrets.SystemRandom, random.Random]) -> int:
    """
    Generate random 32-bit value from ARM Thumb-2 single-instruction loadable set.

    Generates from:
    - MOVW range: 65,536 values (80% probability - largest set)
    - MOV modified immediate: ~1,024 values (10% probability)
    - MVN modified immediate: ~1,024 values (10% probability)

    Args:
        rng: Random number generator

    Returns:
        Random 32-bit value loadable with single ARM Thumb-2 32-bit instruction
    """
    choice = rng.random()

    if choice < 0.8:
        # MOVW: 16-bit immediate zero-extended (most common)
        return rng.randint(0, 0xFFFF)
    elif choice < 0.9:
        # MOV with modified immediate: random encoding
        imm12 = rng.randint(0, 4095)
        return expand_arm_modified_immediate(imm12)
    else:
        # MVN: bitwise NOT of modified immediate
        imm12 = rng.randint(0, 4095)
        value = expand_arm_modified_immediate(imm12)
        return (~value) & 0xFFFFFFFF


def generate_arch_candidate_from_set(valid_set: set,
                                     rng: Union[secrets.SystemRandom, random.Random]) -> int:
    """
    Generate random candidate by uniformly sampling from pre-computed valid set.

    This is slower than specialized generators but ensures uniform distribution.

    Args:
        valid_set: Pre-computed set of valid values
        rng: Random number generator

    Returns:
        Random value from valid set
    """
    # Convert set to list for random access (cached by caller for efficiency)
    valid_list = list(valid_set)
    return rng.choice(valid_list)


def find_best_candidate(existing: List[int], bit_width: int,
                        min_required_distance: int,
                        candidates_per_round: int,
                        rng: Union[secrets.SystemRandom, random.Random],
                        check_weak: bool = True,
                        check_clustering: bool = False,
                        min_distribution_score: float = 40.0,
                        arch_mode: Optional[str] = None,
                        arch_valid_set: Optional[set] = None) -> Optional[int]:
    """
    Find the best candidate constant that maximizes minimum distance.

    Optionally also considers bit difference clustering to prefer
    candidates with well-distributed differences.

    Architecture constraints (if arch_mode specified):
    - Generates only values loadable with single instruction
    - Validates against pre-computed valid set if provided

    Args:
        existing: List of existing constants
        bit_width: Number of bits
        min_required_distance: Minimum required distance
        candidates_per_round: Number of candidates to test
        rng: Random number generator
        check_weak: Whether to reject weak patterns
        check_clustering: Whether to check bit difference clustering
        min_distribution_score: Minimum distribution score (0-100) when check_clustering=True
        arch_mode: Architecture mode ('riscv', 'arm', or None)
        arch_valid_set: Pre-computed set of valid values for architecture

    Returns:
        Best candidate or None if none meets requirements
    """
    best_candidate = None
    best_min_distance = 0
    best_avg_distribution = 0.0
    max_val = (1 << bit_width) - 1

    for _ in range(candidates_per_round):
        # Generate candidate based on architecture mode
        if arch_mode == 'riscv':
            candidate = generate_riscv_candidate(rng)
        elif arch_mode == 'arm':
            candidate = generate_arm_candidate(rng)
        else:
            # Standard generation (no architecture constraints)
            candidate = generate_balanced_constant(bit_width, rng, check_weak=check_weak)

        # Validate against architecture constraints if set provided
        if arch_valid_set is not None and candidate not in arch_valid_set:
            continue

        # Skip if duplicate
        if candidate in existing:
            continue

        # Check if candidate is bitwise complement of any existing constant
        candidate_complement = candidate ^ max_val
        if candidate_complement in existing:
            continue

        # Calculate minimum distance to existing constants
        if existing:
            min_dist = min(hamming_distance(candidate, c) for c in existing)
        else:
            min_dist = bit_width  # First constant, use max possible

        # Check if meets minimum distance requirement
        if min_dist < min_required_distance:
            continue

        # Calculate distribution quality if clustering check enabled
        avg_distribution = 100.0  # Default to perfect if not checking
        if check_clustering and existing:
            distribution_scores = []
            for const in existing:
                cluster_info = analyze_bit_clustering(candidate, const, bit_width)
                score = calculate_distribution_score(cluster_info, bit_width)
                distribution_scores.append(score)

            avg_distribution = sum(distribution_scores) / len(distribution_scores)

            # Skip candidates with poor distribution
            if avg_distribution < min_distribution_score:
                continue

        # Select best candidate based on:
        # 1. Primary: Hamming distance
        # 2. Secondary: Distribution score (if checking clustering)
        is_better = False
        if min_dist > best_min_distance:
            is_better = True
        elif min_dist == best_min_distance and check_clustering:
            # Same distance, prefer better distribution
            if avg_distribution > best_avg_distribution:
                is_better = True

        if is_better:
            best_candidate = candidate
            best_min_distance = min_dist
            best_avg_distribution = avg_distribution

    return best_candidate


def generate_constants(bit_width: int,
                      num_constants: int,
                      min_required_distance: int,
                      max_attempts: int = 100,
                      candidates_per_round: int = 1000,
                      seed: Optional[int] = None,
                      check_weak: bool = True,
                      check_clustering: bool = False,
                      min_distribution_score: float = 40.0,
                      arch_mode: Optional[str] = None,
                      arch_valid_set: Optional[set] = None) -> GenerationResult:
    """
    Generate a set of constants with specified minimum Hamming distance.

    Architecture constraints (if arch_mode specified):
    - All generated constants will be loadable with single instruction
    - For RISC-V: ~1M valid values (0.024% of 2^32)
    - For ARM: ~67k valid values (0.0016% of 2^32)

    Args:
        bit_width: Bit width of constants (8-64)
        num_constants: Number of constants to generate
        min_required_distance: Minimum required Hamming distance
        max_attempts: Maximum number of generation attempts
        candidates_per_round: Number of candidates to test per round
        seed: Optional random seed for reproducibility
        check_weak: Whether to reject weak patterns (default: True)
        check_clustering: Whether to check bit difference clustering (default: False)
        min_distribution_score: Minimum distribution score when check_clustering=True (default: 40.0)
        arch_mode: Architecture mode ('riscv', 'arm', or None for unconstrained)
        arch_valid_set: Pre-computed set of valid values (optional, for validation)

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
        if arch_mode == 'riscv':
            constants.append(generate_riscv_candidate(rng))
        elif arch_mode == 'arm':
            constants.append(generate_arm_candidate(rng))
        else:
            constants.append(generate_balanced_constant(bit_width, rng, check_weak=check_weak))

        # Greedily add remaining constants
        success = True
        for _ in range(num_constants - 1):
            candidate = find_best_candidate(
                constants, bit_width, min_required_distance,
                candidates_per_round, rng, check_weak=check_weak,
                check_clustering=check_clustering,
                min_distribution_score=min_distribution_score,
                arch_mode=arch_mode,
                arch_valid_set=arch_valid_set
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
                              check_weak: bool = True,
                              check_clustering: bool = False,
                              min_distribution_score: float = 40.0,
                              arch_mode: Optional[str] = None,
                              arch_valid_set: Optional[set] = None) -> Tuple[int, GenerationResult]:
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
        check_clustering: Whether to check bit difference clustering
        min_distribution_score: Minimum distribution score when check_clustering=True
        arch_mode: Architecture mode ('riscv', 'arm', or None)
        arch_valid_set: Pre-computed set of valid values

    Returns:
        Tuple of (achieved_distance, generation_result)
    """
    # Get theoretical maximum as starting point
    theoretical_max, bound_name = calculate_theoretical_max_distance(bit_width, num_constants)

    if arch_mode:
        print(f"Auto-discovery mode with {arch_mode.upper()} constraints:")
        print(f"Valid set size: {len(arch_valid_set) if arch_valid_set else 'unknown'} values")
        print(f"Unconstrained theoretical maximum is d ≤ {theoretical_max} ({bound_name} bound)")
        print(f"Searching for maximum achievable distance with architecture constraints...\n")
    else:
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
            check_weak=check_weak,
            check_clustering=check_clustering,
            min_distribution_score=min_distribution_score,
            arch_mode=arch_mode,
            arch_valid_set=arch_valid_set
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


def parse_constants_from_file(file_path: str) -> Tuple[List[int], Optional[int]]:
    """
    Parse constants from an input file.

    Supports multiple formats:
    - Hexadecimal: 0xABCD, 0XABCD, ABCDh, $ABCD
    - Decimal: 12345
    - Binary: 0b1010, 0B1010, 1010b
    - C-style: #define CONST 0x1234
    - Comments: // or # or /* */

    Args:
        file_path: Path to input file

    Returns:
        Tuple of (constants_list, detected_bit_width)
        bit_width is auto-detected from maximum value, or None if empty
    """
    import re

    constants = []

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            # Remove comments
            line = re.sub(r'//.*$', '', line)  # C++ style
            line = re.sub(r'#.*$', '', line)   # Python/shell style
            line = re.sub(r'/\*.*?\*/', '', line)  # C style

            # Find all number-like tokens
            # Hex: 0x1234, 0X1234, 1234h, $1234
            hex_matches = re.findall(r'\b0[xX]([0-9a-fA-F]+)\b|\b([0-9a-fA-F]+)[hH]\b|\$([0-9a-fA-F]+)\b', line)
            for match in hex_matches:
                hex_str = match[0] or match[1] or match[2]
                try:
                    constants.append(int(hex_str, 16))
                except ValueError:
                    pass

            # Binary: 0b1010, 0B1010, 1010b
            bin_matches = re.findall(r'\b0[bB]([01]+)\b|\b([01]+)[bB]\b', line)
            for match in bin_matches:
                bin_str = match[0] or match[1]
                try:
                    constants.append(int(bin_str, 2))
                except ValueError:
                    pass

            # Decimal: plain numbers (but avoid matching hex digits)
            # Only match if no hex prefix and not followed by h or within hex context
            if not hex_matches and not bin_matches:
                dec_matches = re.findall(r'\b(\d+)\b', line)
                for dec_str in dec_matches:
                    try:
                        val = int(dec_str, 10)
                        # Sanity check: reasonable range for constants
                        if 0 <= val <= 0xFFFFFFFFFFFFFFFF:
                            constants.append(val)
                    except ValueError:
                        pass

    if not constants:
        return [], None

    # Remove duplicates while preserving order
    seen = set()
    unique_constants = []
    for c in constants:
        if c not in seen:
            seen.add(c)
            unique_constants.append(c)

    # Auto-detect bit width from maximum value
    max_val = max(unique_constants)
    if max_val == 0:
        bit_width = 8
    else:
        bit_width = max_val.bit_length()
        # Round up to nearest power of 2 or common size
        if bit_width <= 8:
            bit_width = 8
        elif bit_width <= 16:
            bit_width = 16
        elif bit_width <= 32:
            bit_width = 32
        else:
            bit_width = 64

    return unique_constants, bit_width


def verify_constants(constants: List[int], bit_width: int,
                     show_clustering: bool = False,
                     clustering_threshold: float = 60.0) -> dict:
    """
    Verify security properties of a set of constants.

    Args:
        constants: List of constants to verify
        bit_width: Bit width of constants
        show_clustering: Whether to analyze bit clustering
        clustering_threshold: Score threshold for clustering analysis

    Returns:
        Dictionary with verification results:
        - min_distance, max_distance, avg_distance
        - weak_patterns: list of (index, value, reason)
        - complement_pairs: list of (index_i, index_j)
        - clustering_analysis: dict or None
        - verdict: "PASS" or "FAIL"
        - issues: list of issue descriptions
    """
    issues = []

    # Calculate distances
    if len(constants) < 2:
        min_dist, max_dist, avg_dist = 0, 0, 0.0
        if len(constants) == 1:
            issues.append("Only one constant provided - cannot calculate distances")
    else:
        min_dist, max_dist, avg_dist = calculate_statistics(constants)

    # Check for weak patterns
    weak_patterns = check_set_for_weak_patterns(constants, bit_width)
    if weak_patterns:
        issues.append(f"{len(weak_patterns)} weak patterns detected")

    # Check for complements
    complement_pairs = check_for_complements(constants, bit_width)
    if complement_pairs:
        issues.append(f"{len(complement_pairs)} complement pairs detected (CRITICAL)")

    # Check for duplicates
    if len(constants) != len(set(constants)):
        issues.append("Duplicate constants detected")

    # Clustering analysis
    clustering_analysis = None
    if show_clustering and len(constants) >= 2:
        # Analyze all pairs and collect statistics
        pair_analyses = []
        for i in range(len(constants)):
            for j in range(i+1, len(constants)):
                cluster_info = analyze_bit_clustering(constants[i], constants[j], bit_width)
                score = calculate_distribution_score(cluster_info, bit_width)
                pair_analyses.append((i, j, score, cluster_info))

        pair_analyses.sort(key=lambda x: x[2])

        poor_pairs = [p for p in pair_analyses if p[2] < clustering_threshold]
        if poor_pairs:
            issues.append(f"{len(poor_pairs)} pairs with poor bit distribution (score < {clustering_threshold})")

        clustering_analysis = {
            'pair_analyses': pair_analyses,
            'poor_pairs': poor_pairs,
            'threshold': clustering_threshold
        }

    # Overall verdict
    verdict = "PASS" if not issues else "FAIL"

    return {
        'min_distance': min_dist if len(constants) >= 2 else None,
        'max_distance': max_dist if len(constants) >= 2 else None,
        'avg_distance': avg_dist if len(constants) >= 2 else None,
        'weak_patterns': weak_patterns,
        'complement_pairs': complement_pairs,
        'clustering_analysis': clustering_analysis,
        'verdict': verdict,
        'issues': issues
    }


def print_verification_report(constants: List[int], bit_width: int,
                              verification: dict, show_details: bool = False,
                              show_histogram: bool = False):
    """
    Print verification report for a set of constants.

    Args:
        constants: List of constants
        bit_width: Bit width of constants
        verification: Verification results from verify_constants()
        show_details: Whether to show detailed analysis
    """
    print(f"\n{'='*70}")
    print(f"CONSTANT VERIFICATION REPORT")
    print(f"{'='*70}")
    print(f"Number of constants: {len(constants)}")
    print(f"Bit width: {bit_width}")
    print(f"{'='*70}\n")

    # Print constants
    print("Constants:")
    hex_width = (bit_width + 3) // 4
    for i, const in enumerate(constants):
        weight = bin(const).count('1')
        print(f"  [{i:2d}]  0x{const:0{hex_width}X}  (weight: {weight}, dec: {const})")

    # Distance statistics
    if verification['min_distance'] is not None:
        print(f"\n{'='*70}")
        print("Hamming Distance Statistics:")
        print(f"{'='*70}")
        print(f"  Minimum distance: {verification['min_distance']}")
        print(f"  Maximum distance: {verification['max_distance']}")
        print(f"  Average distance: {verification['avg_distance']:.2f}")

        # Show theoretical maximum
        if len(constants) >= 2:
            theoretical_max, bound_name = calculate_theoretical_max_distance(bit_width, len(constants))
            efficiency = (verification['min_distance'] / theoretical_max * 100) if theoretical_max > 0 else 0
            print(f"  Theoretical max:  {theoretical_max} ({bound_name} bound)")
            print(f"  Efficiency:       {efficiency:.1f}% of theoretical maximum")
        print(f"{'='*70}\n")

    # Weak patterns
    if verification['weak_patterns']:
        print(f"{'='*70}")
        print(f"⚠ WARNING: Weak Patterns Detected ({len(verification['weak_patterns'])} constants)")
        print(f"{'='*70}")
        for idx, value, reason in verification['weak_patterns']:
            print(f"  [{idx:2d}]  0x{value:0{hex_width}X}  - {reason}")
        print(f"{'='*70}\n")

    # Complement pairs
    if verification['complement_pairs']:
        print(f"{'='*70}")
        print(f"⚠ CRITICAL: Bitwise Complement Pairs ({len(verification['complement_pairs'])} pairs)")
        print(f"{'='*70}")
        print("A single stuck-at fault affecting all bits can transform one constant")
        print("into another, compromising security!\n")
        for i, j in verification['complement_pairs']:
            print(f"  [{i:2d}]  0x{constants[i]:0{hex_width}X}  <-->  [{j:2d}]  0x{constants[j]:0{hex_width}X}")
        print(f"{'='*70}\n")

    # Distance matrix
    if len(constants) >= 2 and len(constants) <= 20:
        print("Hamming Distance Matrix:")
        print("      ", end="")
        for i in range(len(constants)):
            print(f"[{i:2d}]", end=" ")
        print()

        matrix = calculate_distance_matrix(constants)
        for i in range(len(constants)):
            print(f"[{i:2d}]  ", end="")
            for j in range(len(constants)):
                if i == j:
                    print("  - ", end=" ")
                else:
                    print(f"{matrix[i][j]:3d}", end=" ")
            print()
        print()

    # Histogram visualization
    if show_histogram and len(constants) >= 2:
        print(f"{'='*70}")
        print("Bit Difference Distribution Analysis:")
        print(f"{'='*70}\n")

        histogram = calculate_bit_difference_histogram(constants, bit_width)

        # Hamming distance histogram
        print(visualize_hamming_distance_histogram(histogram))

        # Bit position heatmap
        print(visualize_bit_position_heatmap(histogram, bit_width))

    # Clustering analysis
    if verification['clustering_analysis']:
        print_clustering_analysis(constants, bit_width, show_details=show_details,
                                  threshold=verification['clustering_analysis']['threshold'])

    # Final verdict
    print(f"{'='*70}")
    if verification['verdict'] == "PASS":
        print(f"✓ VERIFICATION PASSED")
        print(f"{'='*70}")
        print("No critical security issues detected.")
    else:
        print(f"✗ VERIFICATION FAILED")
        print(f"{'='*70}")
        print(f"Issues found ({len(verification['issues'])}):")
        for issue in verification['issues']:
            print(f"  - {issue}")
    print(f"{'='*70}\n")


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
                 output_format: str = "default", prefix: str = "SECURE_CONST",
                 show_clustering: bool = False, clustering_threshold: float = 60.0,
                 show_histogram: bool = False,
                 arch_mode: Optional[str] = None,
                 arch_valid_set: Optional[set] = None):
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
        show_clustering: Whether to show bit difference clustering analysis
        clustering_threshold: Score threshold for flagging pairs (default: 60.0)
        show_histogram: Whether to show bit difference histogram
        arch_mode: Architecture mode ('riscv', 'arm', or None)
        arch_valid_set: Pre-computed set of valid values
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

    # Print architecture-specific instruction encodings
    if arch_mode:
        print(f"{'='*70}")
        print(f"Architecture: {arch_mode.upper()} - Single-Instruction Loadable")
        print(f"{'='*70}")
        if arch_valid_set:
            print(f"Valid set size: {len(arch_valid_set):,} values ({len(arch_valid_set)/2**32*100:.4f}% of 2^32)")
        print(f"\nInstruction encodings:")

        if arch_mode == 'riscv':
            desc_fn = describe_riscv_instruction
        else:  # arm
            desc_fn = describe_arm_instruction

        for i, const in enumerate(result.constants):
            instr = desc_fn(const)
            print(f"  [{i:2d}]  0x{const:08X}  →  {instr}")

        print(f"\n✓ All {len(result.constants)} constants loadable in single {arch_mode.upper()} instruction")
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

    # Check for bitwise complements
    complement_pairs = check_for_complements(result.constants, bit_width)
    if complement_pairs:
        print(f"{'='*70}")
        print(f"⚠ CRITICAL: Bitwise complement pairs detected ({len(complement_pairs)} pairs)")
        print(f"{'='*70}")
        print("A single stuck-at fault affecting all bits can transform one constant")
        print("into another, compromising security!\n")
        hex_width = (bit_width + 3) // 4
        for i, j in complement_pairs:
            print(f"  [{i:2d}]  0x{result.constants[i]:0{hex_width}X}  <-->  [{j:2d}]  0x{result.constants[j]:0{hex_width}X}")
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

    # Add histogram visualization if requested
    if show_histogram and len(result.constants) >= 2:
        print(f"{'='*70}")
        print("Bit Difference Distribution Analysis:")
        print(f"{'='*70}\n")

        histogram = calculate_bit_difference_histogram(result.constants, bit_width)

        # Hamming distance histogram
        print(visualize_hamming_distance_histogram(histogram))

        # Bit position heatmap
        print(visualize_bit_position_heatmap(histogram, bit_width))

    # Add clustering analysis if requested
    if show_clustering:
        print_clustering_analysis(result.constants, bit_width,
                                 show_details=True, threshold=clustering_threshold)

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
        description='Generate or verify secure constants with maximum Hamming distance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generation mode:
    Auto-discover maximum distance for 10 32-bit constants:
      %(prog)s --bits 32 --count 10

    Generate 10 32-bit constants with minimum distance 16:
      %(prog)s --bits 32 --count 10 --min-distance 16

    Generate 5 16-bit constants with minimum distance 8:
      %(prog)s -b 16 -c 5 -m 8

    Output in C enum format:
      %(prog)s -b 32 -c 10 --format c-enum

    Generate RISC-V RV32I single-instruction loadable constants:
      %(prog)s -b 32 -c 10 --arch riscv

    Generate ARM Thumb-2 single-instruction loadable constants:
      %(prog)s -b 32 -c 10 --arch arm

  Verification mode:
    Verify constants from file (auto-detect bit width):
      %(prog)s --verify constants.txt

    Verify with explicit bit width:
      %(prog)s --verify constants.txt --bits 32

    Verify with histogram visualization:
      %(prog)s --verify constants.txt --show-histogram

    Verify with clustering analysis:
      %(prog)s --verify constants.txt --show-clustering
        """
    )

    # Mode selection
    parser.add_argument('--verify', type=str, metavar='FILE',
                       help='Verification mode: analyze constants from FILE')

    # Generation/verification parameters
    parser.add_argument('-b', '--bits', type=int,
                       help='Bit width of constants (8-64, auto-detected in verify mode)')
    parser.add_argument('-c', '--count', type=int,
                       help='Number of constants to generate (generation mode only)')
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
    parser.add_argument('--check-clustering', action='store_true',
                       help='Enable bit difference clustering optimization during generation')
    parser.add_argument('--min-distribution-score', type=float, default=40.0,
                       help='Minimum distribution quality score when --check-clustering enabled (0-100, default: 40)')
    parser.add_argument('--show-clustering', action='store_true',
                       help='Show detailed bit difference clustering analysis in output')
    parser.add_argument('--show-histogram', action='store_true',
                       help='Show bit difference distribution histogram and heatmap')
    parser.add_argument('--arch', type=str, choices=['riscv', 'arm'],
                       help='Architecture constraint: generate only single-instruction loadable constants (riscv=RV32I, arm=Thumb-2)')

    args = parser.parse_args()

    # Architecture mode setup
    arch_mode = args.arch if hasattr(args, 'arch') else None
    arch_valid_set = None

    if arch_mode:
        # Pre-compute valid set for architecture
        print(f"Architecture mode: {arch_mode.upper()}")
        print(f"Pre-computing valid instruction set... ", end='', flush=True)
        if arch_mode == 'riscv':
            arch_valid_set = precompute_riscv_valid_set()
        elif arch_mode == 'arm':
            arch_valid_set = precompute_arm_valid_set()
        print(f"done ({len(arch_valid_set):,} valid values)\n")

    # Verification mode
    if args.verify:
        try:
            constants, detected_bit_width = parse_constants_from_file(args.verify)
        except FileNotFoundError:
            print(f"ERROR: File not found: {args.verify}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"ERROR: Failed to parse file: {e}", file=sys.stderr)
            return 2

        if not constants:
            print(f"ERROR: No constants found in file: {args.verify}", file=sys.stderr)
            return 2

        # Use explicit bit width if provided, otherwise use detected
        bit_width = args.bits if args.bits else detected_bit_width

        print(f"Loaded {len(constants)} constants from {args.verify}")
        if args.bits:
            print(f"Using bit width: {bit_width} (user-specified)")
        else:
            print(f"Detected bit width: {bit_width} (auto-detected from max value)")

        # Verify constants
        verification = verify_constants(
            constants=constants,
            bit_width=bit_width,
            show_clustering=args.show_clustering,
            clustering_threshold=args.min_distribution_score
        )

        # Print report
        print_verification_report(
            constants=constants,
            bit_width=bit_width,
            verification=verification,
            show_details=args.show_clustering,
            show_histogram=args.show_histogram
        )

        return 0 if verification['verdict'] == "PASS" else 1

    # Generation mode - validate parameters
    if not args.bits or not args.count:
        print("ERROR: Generation mode requires --bits and --count arguments", file=sys.stderr)
        print("       Use --verify FILE for verification mode", file=sys.stderr)
        return 2

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
            seed=args.seed,
            check_clustering=args.check_clustering,
            min_distribution_score=args.min_distribution_score,
            arch_mode=arch_mode,
            arch_valid_set=arch_valid_set
        )

        if result.success:
            print()  # Blank line before results
            print_results(result, args.bits, args.count, achieved_distance, args.show_bounds, auto_mode=True,
                         output_format=args.output_format, prefix=args.prefix,
                         show_clustering=args.show_clustering, clustering_threshold=args.min_distribution_score,
                         show_histogram=args.show_histogram,
                         arch_mode=arch_mode, arch_valid_set=arch_valid_set)
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
            seed=args.seed,
            check_clustering=args.check_clustering,
            min_distribution_score=args.min_distribution_score,
            arch_mode=arch_mode,
            arch_valid_set=arch_valid_set
        )

        # Print results
        print_results(result, args.bits, args.count, args.min_distance, args.show_bounds, auto_mode=False,
                     output_format=args.output_format, prefix=args.prefix,
                     show_clustering=args.show_clustering, clustering_threshold=args.min_distribution_score,
                     show_histogram=args.show_histogram,
                     arch_mode=arch_mode, arch_valid_set=arch_valid_set)

        # Return appropriate exit code
        return 0 if result.success else 1


if __name__ == '__main__':
    sys.exit(main())
