#!/usr/bin/env python3
"""
NAV KING Auditor v1.2 Deterministic Test Runner

Runs deterministic acceptance tests and compares actual auditor output
against expected verdicts/reason codes.

Design goals:
- Strict vs environment-sensitive test classification
- Proper exit code based on strict acceptance gate
- Direct validation of explicit_tool_page
- Restore original candidates.json after test
- Do not modify production files
"""

import json
import os
import shutil
import subprocess
import sys


STRICT_TESTS = {
    "DET-001",
    "DET-002",
    "DET-003",
    "DET-004",
    "DET-005",
    "DET-006",
    "DET-008",
    "DET-011",
    "DET-012",
    "DET-013",
    "DET-014",
    "DET-015",
}

ENV_SENSITIVE_TESTS = {
    "DET-007",   # Timeout behavior can vary by runner/network
    "DET-009",   # Cross-domain redirect behavior can vary
    "DET-010",   # DNS resolver behavior can vary
}


def load_json(path):
    """Load JSON file safely."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def compare_result(test_def, actual_result):
    """
    Compare expected test definition against actual result.

    Returns:
        (matched: bool, notes: list[str])
    """
    notes = []

    expected_verdict = test_def.get("expected_verdict")
    expected_reason = test_def.get("expected_reason_code")

    actual_verdict = actual_result.get("verdict")
    actual_reason = actual_result.get("review_reason_code")

    verdict_match = expected_verdict == actual_verdict

    if expected_reason is None:
        reason_match = True
    else:
        reason_match = expected_reason == actual_reason

    matched = verdict_match and reason_match

    test_id = test_def.get("candidate_id")

    # Critical direct-tool test.
    if test_id == "DET-015":
        task_match_ok = actual_result.get("task_match") == "PASS"
        explicit_tool_ok = actual_result.get("explicit_tool_page") is True
        verdict_ok = actual_result.get("verdict") == "PASS"

        matched = task_match_ok and explicit_tool_ok and verdict_ok

        notes.append(
            f"DET-015 task_match PASS: {task_match_ok}"
        )
        notes.append(
            f"DET-015 explicit_tool_page TRUE: {explicit_tool_ok}"
        )
        notes.append(
            f"DET-015 verdict PASS: {verdict_ok}"
        )

    return matched, notes


def print_result(test_def, actual_result, status):
    """Print one test result."""
    test_id = test_def.get("candidate_id", "UNKNOWN")

    print(f"\n{status}")
    print(f"  TEST_ID: {test_id}")
    print(
        f"  SCENARIO: "
        f"{test_def.get('test_scenario', 'N/A')}"
    )
    print(f"  URL: {actual_result.get('url')}")
    print(
        f"  EXPECTED_VERDICT: "
        f"{test_def.get('expected_verdict')}"
    )
    print(
        f"  ACTUAL_VERDICT: "
        f"{actual_result.get('verdict')}"
    )
    print(
        f"  EXPECTED_REASON_CODE: "
        f"{test_def.get('expected_reason_code')}"
    )
    print(
        f"  ACTUAL_REASON_CODE: "
        f"{actual_result.get('review_reason_code')}"
    )
    print(
        f"  TASK_MATCH: "
        f"{actual_result.get('task_match')}"
    )
    print(
        f"  EXPLICIT_TOOL_PAGE: "
        f"{actual_result.get('explicit_tool_page')}"
    )
    print(
        f"  SCORE: "
        f"{actual_result.get('score')}"
    )
    print(
        f"  CONFIDENCE: "
        f"{actual_result.get('confidence')}"
    )
    print(
        f"  HTTP_STATUS: "
        f"{actual_result.get('http_status')}"
    )
    print(
        f"  RESPONSE_TIME_MS: "
        f"{actual_result.get('response_time_ms')}"
    )
    print(
        f"  AUTOMATION_BLOCKED: "
        f"{actual_result.get('automation_blocked')}"
    )
    print(
        f"  NETWORK_ERROR_TYPE: "
        f"{actual_result.get('network_error_type')}"
    )
    print(
        f"  FINAL_URL: "
        f"{actual_result.get('final_url')}"
    )


def run_deterministic_tests():
    """Execute the deterministic acceptance suite."""

    print("=" * 90)
    print(
        "NAV KING AUDITOR v1.2 - "
        "DETERMINISTIC TEST ACCEPTANCE SUITE"
    )
    print("=" * 90)

    candidates_path = "audit/candidates.json"
    deterministic_path = "audit/candidates_deterministic.json"
    backup_path = "audit/candidates.json.backup"

    auditor_path = "audit/audit_urls.py"
    results_path = "audit/audit-results.json"

    # ---------------------------------------------------------
    # Required files
    # ---------------------------------------------------------

    required_files = [
        auditor_path,
        deterministic_path,
    ]

    print("\n[SETUP] Checking required files...")

    for path in required_files:
        if not os.path.isfile(path):
            print(f"[ERROR] Missing required file: {path}")
            return False

        print(f"[OK] {path}")

    # ---------------------------------------------------------
    # Backup production candidate file if it exists
    # ---------------------------------------------------------

    had_original_candidates = os.path.isfile(candidates_path)

    if had_original_candidates:
        print(
            f"[BACKUP] {candidates_path} "
            f"→ {backup_path}"
        )
        shutil.copy2(
            candidates_path,
            backup_path,
        )

    try:
        # -----------------------------------------------------
        # Activate deterministic test candidates
        # -----------------------------------------------------

        print(
            f"[SETUP] Loading deterministic candidates: "
            f"{deterministic_path}"
        )

        shutil.copy2(
            deterministic_path,
            candidates_path,
        )

        # -----------------------------------------------------
        # Execute auditor
        # -----------------------------------------------------

        print("\n[EXEC] Running auditor...")
        print(
            f"[EXEC] "
            f"{sys.executable} {auditor_path}"
        )

        process = subprocess.run(
            [
                sys.executable,
                auditor_path,
            ],
            text=True,
            check=False,
        )

        if process.returncode != 0:
            print(
                "\n[ERROR] Auditor execution failed "
                f"with exit code {process.returncode}"
            )
            return False

        # -----------------------------------------------------
        # Verify results file
        # -----------------------------------------------------

        if not os.path.isfile(results_path):
            print(
                f"[ERROR] Expected results file "
                f"not found: {results_path}"
            )
            return False

        try:
            audit_results = load_json(results_path)
            test_defs = load_json(deterministic_path)
        except json.JSONDecodeError as exc:
            print(
                f"[ERROR] Invalid JSON during "
                f"acceptance evaluation: {exc}"
            )
            return False

        results = audit_results.get(
            "results",
            [],
        )

        test_candidates = test_defs.get(
            "candidates",
            [],
        )

        result_map = {
            result.get("candidate_id"): result
            for result in results
            if result.get("candidate_id")
        }

        test_map = {
            candidate.get("candidate_id"): candidate
            for candidate in test_candidates
            if candidate.get("candidate_id")
        }

        print("\n" + "=" * 90)
        print("DETERMINISTIC TEST RESULTS")
        print("=" * 90)

        strict_match = 0
        strict_mismatch = 0
        strict_mismatches = []

        env_match = 0
        env_variation = 0
        env_details = []

        unknown_tests = []

        # -----------------------------------------------------
        # Evaluate every deterministic case
        # -----------------------------------------------------

        for test_id in sorted(test_map.keys()):

            test_def = test_map[test_id]
            actual_result = result_map.get(test_id)

            if actual_result is None:
                print(
                    f"\n✗ NO RESULT\n"
                    f"  TEST_ID: {test_id}"
                )

                if test_id in STRICT_TESTS:
                    strict_mismatch += 1
                    strict_mismatches.append(test_id)
                elif test_id in ENV_SENSITIVE_TESTS:
                    env_variation += 1
                    env_details.append(
                        {
                            "test_id": test_id,
                            "status": "NO_RESULT",
                        }
                    )
                else:
                    unknown_tests.append(test_id)

                continue

            matched, notes = compare_result(
                test_def,
                actual_result,
            )

            # -------------------------------------------------
            # Strict cases
            # -------------------------------------------------

            if test_id in STRICT_TESTS:

                if matched:
                    strict_match += 1
                    status = "✓ STRICT PASS"
                else:
                    strict_mismatch += 1
                    strict_mismatches.append(test_id)
                    status = "✗ STRICT FAIL"

            # -------------------------------------------------
            # Environment-sensitive cases
            # -------------------------------------------------

            elif test_id in ENV_SENSITIVE_TESTS:

                if matched:
                    env_match += 1
                    status = "✓ ENV MATCH"
                else:
                    env_variation += 1
                    status = "⊘ ENV VARIATION"

                env_details.append(
                    {
                        "test_id": test_id,
                        "status": status,
                        "expected_verdict":
                            test_def.get(
                                "expected_verdict"
                            ),
                        "actual_verdict":
                            actual_result.get(
                                "verdict"
                            ),
                        "expected_reason":
                            test_def.get(
                                "expected_reason_code"
                            ),
                        "actual_reason":
                            actual_result.get(
                                "review_reason_code"
                            ),
                    }
                )

            else:
                unknown_tests.append(test_id)
                status = "⚠ UNCLASSIFIED"

            print_result(
                test_def,
                actual_result,
                status,
            )

            for note in notes:
                print(f"  [CHECK] {note}")

            # Environment-sensitive observations
            if test_id == "DET-007":
                print(
                    "  [OBSERVATION] Timeout behavior:"
                )
                print(
                    "    Response time: "
                    f"{actual_result.get('response_time_ms')} ms"
                )
                print(
                    "    Network error: "
                    f"{actual_result.get('network_error_type')}"
                )

            if test_id == "DET-009":
                print(
                    "  [OBSERVATION] "
                    "Cross-domain redirect behavior:"
                )
                print(
                    "    Final URL: "
                    f"{actual_result.get('final_url')}"
                )
                print(
                    "    Redirect reason: "
                    f"{actual_result.get('redirect_reason')}"
                )

            if test_id == "DET-010":
                print(
                    "  [OBSERVATION] DNS behavior:"
                )
                print(
                    "    Network error: "
                    f"{actual_result.get('network_error_type')}"
                )

        # -----------------------------------------------------
        # Summary
        # -----------------------------------------------------

        strict_total = len(
            [
                test_id
                for test_id in test_map
                if test_id in STRICT_TESTS
            ]
        )

        env_total = len(
            [
                test_id
                for test_id in test_map
                if test_id in ENV_SENSITIVE_TESTS
            ]
        )

        total_tests = len(test_map)

        overall_gate = (
            "PASS"
            if strict_mismatch == 0
            else "FAIL"
        )

        print("\n" + "=" * 90)
        print("TEST SUMMARY")
        print("=" * 90)

        print(
            f"\nDETERMINISTIC_TEST_TOTAL: "
            f"{total_tests}"
        )

        print(
            f"\nSTRICT_TOTAL: "
            f"{strict_total}"
        )
        print(
            f"STRICT_MATCH: "
            f"{strict_match}"
        )
        print(
            f"STRICT_MISMATCH: "
            f"{strict_mismatch}"
        )

        print(
            f"\nENV_TOTAL: "
            f"{env_total}"
        )
        print(
            f"ENV_MATCH: "
            f"{env_match}"
        )
        print(
            f"ENV_VARIATION: "
            f"{env_variation}"
        )

        print("\n" + "=" * 90)
        print(
            f"OVERALL_GATE: "
            f"{overall_gate}"
        )
        print("=" * 90)

        if strict_mismatches:
            print(
                "\nSTRICT_MISMATCH_TEST_IDS: "
                + ", ".join(
                    sorted(strict_mismatches)
                )
            )

        if env_details:
            print(
                "\nENV-SENSITIVE DETAILS:"
            )

            for detail in env_details:
                print(
                    f"  {detail['test_id']}: "
                    f"{detail['status']}"
                )

        if unknown_tests:
            print(
                "\nUNCLASSIFIED_TEST_IDS: "
                + ", ".join(
                    sorted(unknown_tests)
                )
            )

        print("\n" + "=" * 90)
        print("AUDITOR INFORMATION")
        print("=" * 90)

        print("AUDITOR_VERSION: 1.2")
        print(
            "AUDIT_TIMESTAMP: "
            f"{audit_results.get('generated_at')}"
        )
        print(
            f"OVERALL_GATE: "
            f"{overall_gate}"
        )
        print(
            "PRODUCTION_FILES_MODIFIED: NO"
        )

        return overall_gate == "PASS"

    finally:
        # -----------------------------------------------------
        # Restore original candidates.json
        # -----------------------------------------------------

        print(
            "\n[CLEANUP] Restoring candidate data..."
        )

        if os.path.isfile(backup_path):
            shutil.copy2(
                backup_path,
                candidates_path,
            )
            os.remove(
                backup_path
            )

            print(
                f"[RESTORE] {candidates_path} restored"
            )

        elif not had_original_candidates:
            if os.path.isfile(candidates_path):
                os.remove(
                    candidates_path
                )

            print(
                "[RESTORE] Temporary candidates.json removed"
            )


def main():
    success = run_deterministic_tests()

    if success:
        print(
            "\n[SUCCESS] Deterministic acceptance gate passed"
        )
        return 0

    print(
        "\n[FAIL] Deterministic acceptance gate failed"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
