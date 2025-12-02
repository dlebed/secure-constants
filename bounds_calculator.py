#!/usr/bin/env python3
"""
Theoretical Bounds Calculator for Error-Correcting Codes

Demonstrates calculation of theoretical maximum minimum Hamming distance
given bit width and number of codewords using various bounds from coding theory.
"""

import math
import sys


def hamming_sphere_volume(n: int, r: int) -> int:
    """Calculate volume of Hamming sphere: V(n,r) = Σ(i=0 to r) C(n,i)"""
    if r > n:
        return 2 ** n
    return sum(math.comb(n, i) for i in range(r + 1))


def singleton_bound(n: int, M: int) -> int:
    """Singleton bound: d ≤ n - ⌈log₂(M)⌉ + 1"""
    if M <= 1:
        return n
    return max(1, n - math.ceil(math.log2(M)) + 1)


def hamming_bound(n: int, M: int) -> int:
    """Hamming (sphere-packing) bound: M · V(n, ⌊(d-1)/2⌋) ≤ 2ⁿ"""
    if M <= 1:
        return n
    max_total = 2 ** n
    for d in range(n, 0, -1):
        t = (d - 1) // 2
        if M * hamming_sphere_volume(n, t) <= max_total:
            return d
    return 1


def plotkin_bound(n: int, M: int) -> int:
    """Plotkin bound (inverse calculation)"""
    if M <= 1:
        return n
    for d in range(n, 0, -1):
        if 2 * d > n:
            if d % 2 == 0:
                max_M = (2 * d) // (2 * d - n) if 2 * d != n else 4 * d
            else:
                max_M = (2 * d + 1) // (2 * d + 1 - n) if 2 * d + 1 != n else 4 * d + 2
        else:
            max_M = 2 ** (n - 2 * (d // 2) + 1)
        if max_M >= M:
            return d
    return 1


def print_bounds_table(n: int, M_values: list):
    """Print a table of bounds for different numbers of codewords"""
    print(f"\n{'='*80}")
    print(f"Theoretical Maximum Minimum Distance for {n}-bit constants")
    print(f"{'='*80}")
    print(f"{'M (codewords)':<15} {'Singleton':<12} {'Hamming':<12} {'Plotkin':<12} {'Best':<12}")
    print(f"{'-'*80}")

    for M in M_values:
        s = singleton_bound(n, M)
        h = hamming_bound(n, M)
        p = plotkin_bound(n, M)
        best = min(s, h, p)
        best_name = ["S", "H", "P"][[s, h, p].index(best)]

        print(f"{M:<15} {s:<12} {h:<12} {p:<12} {best} ({best_name})")

    print(f"{'='*80}\n")


def main():
    print("Theoretical Bounds Calculator")
    print("=" * 80)

    # Example 1: 32-bit constants
    print("\nExample 1: 32-bit Constants")
    print_bounds_table(32, [2, 4, 8, 10, 16, 32, 64, 128, 256])

    # Example 2: 16-bit constants
    print("\nExample 2: 16-bit Constants")
    print_bounds_table(16, [2, 4, 8, 16, 32, 64, 128, 256])

    # Example 3: 8-bit constants
    print("\nExample 3: 8-bit Constants")
    print_bounds_table(8, [2, 4, 8, 16, 32, 64])

    # Interactive mode
    if len(sys.argv) == 3:
        n = int(sys.argv[1])
        M = int(sys.argv[2])
        print(f"\nCalculating bounds for {M} codewords of {n} bits:")
        s = singleton_bound(n, M)
        h = hamming_bound(n, M)
        p = plotkin_bound(n, M)
        best = min(s, h, p)

        print(f"  Singleton bound: d ≤ {s}")
        print(f"  Hamming bound:   d ≤ {h}")
        print(f"  Plotkin bound:   d ≤ {p}")
        print(f"  Tightest bound:  d ≤ {best}")
        print()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print("Usage: python3 bounds_calculator.py [n] [M]")
        print("  n: bit width")
        print("  M: number of codewords")
        print("\nIf no arguments given, shows example tables")
        sys.exit(0)

    main()
