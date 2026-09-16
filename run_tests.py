"""
run_tests.py

Unified cross-platform test runner for the Sysmon codebase.
Runs agent, backend, and worker test suites in isolated environments.
"""

import subprocess
import sys


def run_suite(name: str, test_dir: str, pythonpath: str) -> bool:
    print(f"\n{'='*60}\n Running {name} Test Suite ({test_dir})\n{'='*60}")
    cmd = [sys.executable, "-m", "pytest", test_dir, "-o", f"pythonpath={pythonpath}", "-v"]
    result = subprocess.run(cmd)
    return result.returncode == 0


def main():
    suites = [
        ("Agent", "agent/tests", "agent"),
        ("Backend", "backend/tests", "backend"),
        ("Worker", "worker/tests", "worker"),
    ]

    all_passed = True
    for name, path, pypath in suites:
        passed = run_suite(name, path, pypath)
        if not passed:
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print(" [PASSED] All Sysmon test suites passed successfully!")
        sys.exit(0)
    else:
        print(" [FAILED] Some tests failed. Check logs above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
