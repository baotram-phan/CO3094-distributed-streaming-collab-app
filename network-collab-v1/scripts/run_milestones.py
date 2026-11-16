"""Run real-socket acceptance tests for Milestones 2, 3 and 4.

python -m scripts.run_milestones
python -m scripts.run_milestones --milestone 3
"""

import argparse
import unittest


MILESTONES = {
    2: ("Basic Client-Server Handshake", "tests.test_bootstrap"),
    3: ("Authentication & State Management", "tests.test_a_b_live_network"),
    4: ("Concurrency Implementation", "tests.test_scalability_10_20"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--milestone", type=int, nargs="+", choices=tuple(MILESTONES), default=[2, 3, 4]
    )
    args = parser.parse_args()
    passed = True
    for number in dict.fromkeys(args.milestone):
        title, module = MILESTONES[number]
        print(f"\n[MILESTONE {number}] {title}", flush=True)
        suite = unittest.defaultTestLoader.loadTestsFromName(module)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        milestone_passed = (
            result.testsRun > 0 and result.wasSuccessful() and not result.skipped
        )
        print(
            f"[MILESTONE {number}] {'PASS' if milestone_passed else 'FAIL'} "
            f"({result.testsRun} tests, {len(result.failures)} failures, "
            f"{len(result.errors)} errors, {len(result.skipped)} skipped)",
            flush=True,
        )
        passed = milestone_passed and passed
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
