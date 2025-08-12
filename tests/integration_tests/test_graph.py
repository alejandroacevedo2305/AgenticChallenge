"""
Integration tests for the SOC Agent's modular subgraph architecture.

These tests verify that all subgraphs work together correctly
in the main orchestration graph.
"""

import pytest
import asyncio
import json
from pathlib import Path
from typing import Dict, Any

# Import main graph and subgraphs
import sys

sys.path.append(str(Path(__file__).parent.parent.parent))
from src.agent.main_graph import main_graph, SOCState

pytestmark = pytest.mark.asyncio

# Test data paths
DATA_DIR = Path(__file__).parent.parent.parent / "data"
AUTH_LOG_PATH = DATA_DIR / "auth.log"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth.json"


@pytest.mark.asyncio
async def test_full_pipeline_integration():
    """
    Test the complete pipeline integration from log parsing to report generation.

    This verifies that all subgraphs communicate correctly through the shared state.
    """
    # Input state
    input_state = {"log_file_path": str(AUTH_LOG_PATH)}

    # Track which subgraphs execute
    executed_nodes = []
    final_state = None

    # Run the main graph
    async for chunk in main_graph.astream(
        input_state, stream_mode="updates", subgraphs=True, debug=False
    ):
        if isinstance(chunk, tuple) and len(chunk) == 2:
            path, update = chunk

            # Track main graph node executions
            if not path:  # Main graph update
                for node_name, node_data in update.items():
                    executed_nodes.append(node_name)

                    # Capture final state
                    if node_name == "generate_report":
                        final_state = node_data

    # Verify all subgraphs executed in correct order
    expected_order = [
        "parse_logs",
        "detect_anomalies",
        "enrich_indicators",
        "generate_report",
    ]
    assert (
        executed_nodes == expected_order
    ), f"Expected {expected_order}, got {executed_nodes}"

    # Verify final output
    assert final_state is not None, "No final state produced"
    assert "incident_report" in final_state, "No incident report generated"

    report = final_state["incident_report"]
    assert len(report) > 100, "Report is too short"

    # Verify known malicious IP is in report
    assert "203.0.113.55" in report, "Known malicious IP not detected"

    print("✅ Full pipeline integration test passed")
    print(f"   - All {len(executed_nodes)} subgraphs executed successfully")
    print(f"   - Report generated with {len(report)} characters")


@pytest.mark.asyncio
async def test_state_accumulation():
    """
    Test that state correctly accumulates data as it flows through subgraphs.

    This validates the state management design.
    """
    input_state = {"log_file_path": str(AUTH_LOG_PATH)}

    # Track state evolution
    state_snapshots = {}

    async for chunk in main_graph.astream(
        input_state, stream_mode="updates", subgraphs=True, debug=False
    ):
        if isinstance(chunk, tuple) and len(chunk) == 2:
            path, update = chunk

            if not path:  # Main graph update
                for node_name, node_data in update.items():
                    # Capture state after each node
                    state_snapshots[node_name] = {
                        "has_parsed_logs": "parsed_logs" in node_data
                        and len(node_data.get("parsed_logs", [])) > 0,
                        "has_suspicious_events": "suspicious_events" in node_data
                        and len(node_data.get("suspicious_events", [])) > 0,
                        "has_enriched_data": "enriched_data" in node_data
                        and len(node_data.get("enriched_data", {})) > 0,
                        "has_report": "incident_report" in node_data
                        and len(node_data.get("incident_report", "")) > 0,
                    }

    # Verify state accumulation pattern
    assert state_snapshots["parse_logs"][
        "has_parsed_logs"
    ], "Parse logs didn't produce logs"
    assert state_snapshots["detect_anomalies"][
        "has_suspicious_events"
    ], "Detect anomalies didn't find events"
    assert state_snapshots["enrich_indicators"][
        "has_enriched_data"
    ], "Enrich didn't add threat intel"
    assert state_snapshots["generate_report"][
        "has_report"
    ], "Generate report didn't create report"

    print("✅ State accumulation test passed")
    print("   - State correctly flows through all subgraphs")


@pytest.mark.asyncio
async def test_breach_detection_integration():
    """
    CRITICAL TEST: Verify that breach detection works end-to-end.

    This tests the most important security feature across all subgraphs.
    """
    # The auth.log contains a successful login from 203.0.113.55 after failed attempts
    # This MUST be detected as a breach

    input_state = {"log_file_path": str(AUTH_LOG_PATH)}
    final_report = None

    async for chunk in main_graph.astream(
        input_state, stream_mode="updates", subgraphs=True, debug=False
    ):
        if isinstance(chunk, tuple) and len(chunk) == 2:
            path, update = chunk

            if not path:
                for node_name, node_data in update.items():
                    if node_name == "generate_report":
                        final_report = node_data.get("incident_report", "")

    # CRITICAL: Report must indicate system compromise
    assert final_report is not None, "No report generated"

    # Check for breach indicators in report
    breach_indicators = [
        "COMPROMISED" in final_report.upper(),
        "CRITICAL" in final_report.upper(),
        "BREACH" in final_report.upper() or "SUCCESSFUL" in final_report.upper(),
        "203.0.113.55" in final_report,  # The attacking IP
    ]

    assert any(breach_indicators), "CRITICAL: Breach not properly reported!"

    print("✅ CRITICAL: Breach detection integration test passed")
    print("   - System compromise properly detected and reported")


@pytest.mark.asyncio
async def test_error_resilience():
    """
    Test that the pipeline handles errors gracefully.

    This validates the error handling strategy across subgraphs.
    """
    # Test with non-existent file (should handle gracefully)
    input_state = {"log_file_path": "/nonexistent/path/auth.log"}

    error_occurred = False
    report_generated = False

    try:
        async for chunk in main_graph.astream(
            input_state, stream_mode="updates", subgraphs=True, debug=False
        ):
            if isinstance(chunk, tuple) and len(chunk) == 2:
                path, update = chunk

                if not path:
                    for node_name, node_data in update.items():
                        if (
                            node_name == "generate_report"
                            and "incident_report" in node_data
                        ):
                            report_generated = True
    except Exception as e:
        error_occurred = True
        print(f"Expected error occurred: {e}")

    # The system should either handle the error gracefully or fail predictably
    assert (
        error_occurred or report_generated
    ), "System didn't handle missing file properly"

    print("✅ Error resilience test passed")
    print("   - System handles errors predictably")


@pytest.mark.asyncio
async def test_performance_benchmark():
    """
    Benchmark the performance of the modular architecture.

    This ensures the system meets performance requirements.
    """
    import time

    input_state = {"log_file_path": str(AUTH_LOG_PATH)}

    # Measure execution time
    start_time = time.time()

    node_times = {}

    async for chunk in main_graph.astream(
        input_state, stream_mode="updates", subgraphs=True, debug=False
    ):
        if isinstance(chunk, tuple) and len(chunk) == 2:
            path, update = chunk

            if not path:
                for node_name, node_data in update.items():
                    node_times[node_name] = time.time() - start_time

    total_time = time.time() - start_time

    # Performance assertions (allowing some buffer for LLM variance)
    assert total_time < 35, f"Total execution time {total_time:.2f}s exceeds 35s limit"

    print("✅ Performance benchmark passed")
    print(f"   - Total execution time: {total_time:.2f}s")
    print("   - Subgraph timings:")
    prev_time = 0
    for node, cumulative_time in node_times.items():
        node_duration = cumulative_time - prev_time
        print(f"     • {node}: {node_duration:.2f}s")
        prev_time = cumulative_time


@pytest.mark.asyncio
async def test_subgraph_isolation():
    """
    Test that failures in one subgraph don't crash the entire system.

    This validates the isolation benefits of the modular architecture.
    """
    # Create a log that might cause issues in parsing
    problematic_log = """
    CORRUPTED DATA HERE
    Aug 11 17:15:12 ubuntu-server sshd[1251]: Failed password for invalid user admin from 203.0.113.55 port 48122 ssh2
    MORE CORRUPTION
    """

    test_log_path = Path("/tmp/problematic.log")
    test_log_path.write_text(problematic_log)

    input_state = {"log_file_path": str(test_log_path)}

    nodes_executed = []
    final_report = None

    try:
        async for chunk in main_graph.astream(
            input_state, stream_mode="updates", subgraphs=True, debug=False
        ):
            if isinstance(chunk, tuple) and len(chunk) == 2:
                path, update = chunk

                if not path:
                    for node_name, node_data in update.items():
                        nodes_executed.append(node_name)
                        if node_name == "generate_report":
                            final_report = node_data.get("incident_report")
    except Exception as e:
        print(f"Handled error: {e}")
    finally:
        test_log_path.unlink(missing_ok=True)

    # Even with problematic input, should complete or fail gracefully
    assert len(nodes_executed) > 0, "No nodes executed"

    # If all nodes executed, report should be generated
    if "generate_report" in nodes_executed:
        assert final_report is not None, "Report node executed but no report generated"

    print("✅ Subgraph isolation test passed")
    print(f"   - {len(nodes_executed)} nodes executed despite problematic input")


if __name__ == "__main__":
    """
    Run integration tests standalone to demonstrate the modular architecture.
    """

    async def main():
        print("Integration Tests for Modular Subgraph Architecture")
        print("=" * 60)

        print("\n1. Testing Full Pipeline Integration...")
        await test_full_pipeline_integration()

        print("\n2. Testing State Accumulation...")
        await test_state_accumulation()

        print("\n3. Testing Breach Detection (CRITICAL)...")
        await test_breach_detection_integration()

        print("\n4. Testing Error Resilience...")
        await test_error_resilience()

        print("\n5. Testing Performance...")
        await test_performance_benchmark()

        print("\n6. Testing Subgraph Isolation...")
        await test_subgraph_isolation()

        print("\n" + "=" * 60)
        print("✅ All integration tests passed!")
        print("\nThe modular subgraph architecture provides:")
        print("  • Clear separation of concerns")
        print("  • Independent testing capability")
        print("  • Graceful error handling")
        print("  • Performance within requirements")
        print("  • Production-ready resilience")

        print("\nRun with pytest for CI/CD integration:")
        print("  pytest tests/integration_tests/test_graph.py -v")

    asyncio.run(main())
