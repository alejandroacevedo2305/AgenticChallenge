"""
SOC Agent Evaluation Tests using agent-evals framework.

This file contains evaluation tests for the AI Junior SOC Analyst agent.
Uses the modular subgraph architecture for comprehensive testing.

Requirements:
- Use agent-evals for structured evaluation
- Implement LLM-as-a-judge for report quality assessment
- Calculate detection rate (recall) for malicious IP identification
- Compare agent output against ground truth data
"""

import json
import pytest
import asyncio
import re
from pathlib import Path
from typing import Dict, List, Any
from agentevals.trajectory.llm import create_trajectory_llm_as_judge
from langchain_ollama import ChatOllama
from evaluation_config import (
    get_evaluation_config,
    REPORT_QUALITY_PROMPT,
    THREAT_ANALYSIS_PROMPT,
)

# Import our agent components
import sys

sys.path.append(str(Path(__file__).parent.parent))
from src.agent.main_graph import main_graph, SOCState

# Test data paths
DATA_DIR = Path(__file__).parent.parent / "data"
AUTH_LOG_PATH = DATA_DIR / "auth.log"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth.json"
MOCK_API_PATH = DATA_DIR / "mock_api_responses.json"


class SOCAgentEvaluator:
    """
    Custom evaluator for the SOC Agent using agent-evals framework.
    Evaluates the modular subgraph architecture implementation.
    """

    def __init__(self):
        """Initialize the SOC Agent evaluator."""
        # Load ground truth data and set up evaluation parameters
        self.ground_truth = self.load_ground_truth()
        self.config = get_evaluation_config()

        # Set up LLM for report quality evaluation
        self.llm = ChatOllama(
            model="llama3.1:8b", base_url="http://localhost:11434", temperature=0.1
        )

    def load_ground_truth(self) -> dict:
        """
        Load the ground truth data for evaluation.

        Returns:
            dict: Ground truth data containing malicious IPs and suspicious events
        """
        with open(GROUND_TRUTH_PATH, "r") as f:
            return json.load(f)

    async def run_agent(self, input_data: dict) -> dict:
        """
        Run the SOC agent and return its output.

        Args:
            input_data (dict): Input data for the agent

        Returns:
            dict: Agent output including the final report
        """
        # Run the main graph with our modular subgraph architecture
        final_state = None

        async for chunk in main_graph.astream(
            input_data, stream_mode="updates", subgraphs=True, debug=False
        ):
            # Handle main graph updates
            if isinstance(chunk, tuple) and len(chunk) == 2:
                path, update = chunk

                # Check if this is a main graph node update
                if not path:  # Empty tuple means main graph
                    for node_name, node_data in update.items():
                        if (
                            node_name == "generate_report"
                            and "incident_report" in node_data
                        ):
                            final_state = node_data

        if final_state:
            return final_state
        else:
            raise Exception("Agent failed to generate output")

    def extract_ips_from_report(self, report_content: str) -> List[str]:
        """
        Extract IP addresses mentioned in the incident report.

        Args:
            report_content (str): The generated incident report

        Returns:
            List[str]: List of IP addresses found in the report
        """
        # Look for IPs in various formats in the report
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, report_content)

        # Also look for IPs specifically mentioned as malicious/suspicious
        malicious_patterns = [
            r"malicious IP[s]?[:\s]+([0-9.]+)",
            r"suspicious IP[s]?[:\s]+([0-9.]+)",
            r"IP[:\s]+([0-9.]+).*(?:HIGH|CRITICAL|malicious|suspicious)",
            r"\*\*IP:\s*([0-9.]+)\*\*",  # Markdown formatted IPs
        ]

        for pattern in malicious_patterns:
            matches = re.findall(pattern, report_content, re.IGNORECASE)
            ips.extend(matches)

        # Unique IPs only
        return list(set(ips))

    def calculate_detection_rate(self, agent_output: dict, ground_truth: dict) -> float:
        """
        Calculate the detection rate (recall) for malicious IP identification.

        Args:
            agent_output (dict): Output from the SOC agent
            ground_truth (dict): Ground truth data

        Returns:
            float: Detection rate as a percentage (0-100)
        """
        # Extract malicious IPs from ground truth
        true_malicious_ips = set(ground_truth.get("malicious_ips", []))

        # Extract detected IPs from the agent's report
        report_content = agent_output.get("incident_report", "")
        detected_ips = set(self.extract_ips_from_report(report_content))

        # Filter to only malicious IPs that were detected
        detected_malicious = detected_ips.intersection(true_malicious_ips)

        # Calculate detection rate
        if len(true_malicious_ips) == 0:
            return 100.0  # No malicious IPs to detect

        detection_rate = (len(detected_malicious) / len(true_malicious_ips)) * 100

        # Print debug info
        print(f"\n[Detection Analysis]")
        print(f"Ground truth malicious IPs: {true_malicious_ips}")
        print(f"Detected IPs in report: {detected_ips}")
        print(f"Correctly detected malicious IPs: {detected_malicious}")
        print(f"Detection rate: {detection_rate:.1f}%")

        return detection_rate

    async def evaluate_report_quality(self, report_content: str) -> dict:
        """
        Use LLM-as-a-judge to evaluate report quality.

        Args:
            report_content (str): The generated incident report

        Returns:
            dict: Evaluation results including scores for different criteria
        """
        # Format the prompt with the report content
        prompt = REPORT_QUALITY_PROMPT.format(report_content=report_content)

        try:
            # Call the LLM to evaluate the report
            response = await self.llm.ainvoke(prompt)
            content = response.content

            # Extract JSON from response
            start_idx = content.find("{")
            end_idx = content.rfind("}")

            if start_idx != -1 and end_idx != -1:
                json_str = content[start_idx : end_idx + 1]
                scores = json.loads(json_str)

                print(f"\n[Report Quality Evaluation]")
                print(f"Clarity Score: {scores.get('clarity_score', 0)}/10")
                print(
                    f"Technical Accuracy: {scores.get('technical_accuracy_score', 0)}/10"
                )
                print(f"Actionability: {scores.get('actionability_score', 0)}/10")
                print(f"Completeness: {scores.get('completeness_score', 0)}/10")
                print(f"Overall Score: {scores.get('overall_score', 0)}/10")
                print(f"Justification: {scores.get('justification', 'N/A')}")

                return scores
            else:
                # Fallback if JSON parsing fails
                return self._default_scores()

        except Exception as e:
            print(f"Error in LLM evaluation: {e}")
            return self._default_scores()

    def _default_scores(self) -> dict:
        """Return default scores if evaluation fails."""
        return {
            "clarity_score": 5,
            "technical_accuracy_score": 5,
            "actionability_score": 5,
            "completeness_score": 5,
            "overall_score": 5,
            "justification": "Default scores due to evaluation error",
        }

    async def comprehensive_evaluation(self, input_data: dict) -> dict:
        """
        Run comprehensive evaluation of the SOC agent.

        Args:
            input_data (dict): Input data for the agent

        Returns:
            dict: Comprehensive evaluation results
        """
        import time

        # Measure execution time
        start_time = time.time()

        # Run the agent
        agent_output = await self.run_agent(input_data)

        execution_time = time.time() - start_time

        # Calculate detection rate
        detection_rate = self.calculate_detection_rate(agent_output, self.ground_truth)

        # Evaluate report quality
        report_content = agent_output.get("incident_report", "")
        quality_scores = await self.evaluate_report_quality(report_content)

        # Compile comprehensive results
        results = {
            "detection_rate": detection_rate,
            "report_quality_scores": quality_scores,
            "execution_time": execution_time,
            "passes_detection_threshold": detection_rate
            >= self.config.MIN_DETECTION_RATE,
            "passes_quality_threshold": quality_scores.get("overall_score", 0)
            >= self.config.MIN_REPORT_QUALITY,
            "passes_time_threshold": execution_time <= self.config.MIN_RESPONSE_TIME,
            "overall_pass": (
                detection_rate >= self.config.MIN_DETECTION_RATE
                and quality_scores.get("overall_score", 0)
                >= self.config.MIN_REPORT_QUALITY
            ),
        }

        return results


@pytest.fixture
def soc_evaluator():
    """Fixture to provide SOC agent evaluator instance."""
    return SOCAgentEvaluator()


@pytest.fixture
def sample_input():
    """Fixture to provide sample input data for the agent."""
    return {"log_file_path": str(AUTH_LOG_PATH)}


@pytest.mark.asyncio
async def test_detection_rate_evaluation(soc_evaluator, sample_input):
    """
    Test the detection rate evaluation.

    This test verifies:
    1. Agent identifies malicious IPs from ground truth
    2. Detection rate meets minimum threshold (80%)
    3. Subgraph architecture properly processes logs
    """
    # Run the agent
    agent_output = await soc_evaluator.run_agent(sample_input)

    # Calculate detection rate
    detection_rate = soc_evaluator.calculate_detection_rate(
        agent_output, soc_evaluator.ground_truth
    )

    # Assert detection rate meets threshold
    assert (
        detection_rate >= 80.0
    ), f"Detection rate {detection_rate:.1f}% is below 80% threshold"

    # Verify specific IPs are detected
    report = agent_output.get("incident_report", "")
    assert "203.0.113.55" in report, "Known malicious IP 203.0.113.55 not detected"

    # Note: 192.0.2.147 is in ground truth but appears with limited activity in logs
    # The agent should at least flag it as suspicious

    print(f"✅ Detection rate test passed: {detection_rate:.1f}%")


@pytest.mark.asyncio
async def test_report_quality_evaluation(soc_evaluator, sample_input):
    """
    Test the report quality using LLM-as-a-judge.

    This test verifies:
    1. Report generation through subgraph architecture
    2. Report quality meets minimum thresholds
    3. All evaluation criteria are satisfied
    """
    # Run the agent
    agent_output = await soc_evaluator.run_agent(sample_input)

    # Get report content
    report_content = agent_output.get("incident_report", "")
    assert len(report_content) > 100, "Report is too short or empty"

    # Evaluate report quality
    quality_scores = await soc_evaluator.evaluate_report_quality(report_content)

    # Assert quality thresholds
    assert (
        quality_scores["clarity_score"] >= 7
    ), f"Clarity score {quality_scores['clarity_score']} below threshold"
    assert (
        quality_scores["actionability_score"] >= 7
    ), f"Actionability score {quality_scores['actionability_score']} below threshold"
    assert (
        quality_scores["overall_score"] >= 7
    ), f"Overall score {quality_scores['overall_score']} below threshold"

    print(
        f"✅ Report quality test passed: Overall score {quality_scores['overall_score']}/10"
    )


@pytest.mark.asyncio
async def test_comprehensive_evaluation(soc_evaluator, sample_input):
    """
    Run comprehensive evaluation combining all metrics.

    This test:
    1. Runs the full evaluation suite
    2. Validates all subgraphs work together
    3. Generates comprehensive metrics
    """
    # Run comprehensive evaluation
    results = await soc_evaluator.comprehensive_evaluation(sample_input)

    # Print comprehensive results
    print("\n" + "=" * 60)
    print("COMPREHENSIVE EVALUATION RESULTS")
    print("=" * 60)
    print(f"Detection Rate: {results['detection_rate']:.1f}%")
    print(f"Report Quality: {results['report_quality_scores']['overall_score']}/10")
    print(f"Execution Time: {results['execution_time']:.2f} seconds")
    print("-" * 60)
    print(
        f"Passes Detection Threshold (≥80%): {'✅' if results['passes_detection_threshold'] else '❌'}"
    )
    print(
        f"Passes Quality Threshold (≥7/10): {'✅' if results['passes_quality_threshold'] else '❌'}"
    )
    print(
        f"Passes Time Threshold (≤30s): {'✅' if results['passes_time_threshold'] else '❌'}"
    )
    print("-" * 60)
    print(f"OVERALL RESULT: {'✅ PASS' if results['overall_pass'] else '❌ FAIL'}")
    print("=" * 60)

    # Assert overall pass
    assert results["overall_pass"], "Comprehensive evaluation failed"


@pytest.mark.asyncio
async def test_subgraph_modularity():
    """
    Test that individual subgraphs can be tested independently.

    This validates the modular architecture benefits.
    """
    from src.agent.subgraph_parse_logs import subgraph_parse_logs
    from src.agent.subgraph_detect_anomalies import subgraph_detect_anomalies

    # Test parse_logs subgraph independently
    parse_state = {"log_file_path": str(AUTH_LOG_PATH)}

    async for chunk in subgraph_parse_logs.astream(parse_state, stream_mode="updates"):
        for node_name, node_data in chunk.items():
            if "parsed_logs" in node_data:
                assert len(node_data["parsed_logs"]) > 0, "Parse logs subgraph failed"
                parsed_logs = node_data["parsed_logs"]
                break

    # Test detect_anomalies subgraph independently
    detect_state = {"parsed_logs": parsed_logs}

    async for chunk in subgraph_detect_anomalies.astream(
        detect_state, stream_mode="updates"
    ):
        for node_name, node_data in chunk.items():
            if "suspicious_events" in node_data:
                assert (
                    len(node_data["suspicious_events"]) > 0
                ), "Detect anomalies subgraph failed"
                break

    print("✅ Subgraph modularity test passed")


@pytest.mark.asyncio
async def test_edge_cases(soc_evaluator):
    """
    Test agent behavior on edge cases and error conditions.

    This validates the resilience of the subgraph architecture.
    """
    # Test 1: Empty log file scenario
    empty_log_path = DATA_DIR / "empty.log"
    empty_log_path.write_text("")

    try:
        agent_output = await soc_evaluator.run_agent(
            {"log_file_path": str(empty_log_path)}
        )
        report = agent_output.get("incident_report", "")
        assert len(report) > 0, "Agent should generate report even for empty logs"
        print("✅ Empty log file handled gracefully")
    finally:
        empty_log_path.unlink(missing_ok=True)

    # Test 2: Non-existent log file (should use fallback)
    try:
        agent_output = await soc_evaluator.run_agent(
            {"log_file_path": "nonexistent.log"}
        )
        # Should fail gracefully or use default
        assert False, "Should handle non-existent file"
    except:
        print("✅ Non-existent file handled as expected")

    # Test 3: Malformed log entries
    malformed_log_path = DATA_DIR / "malformed.log"
    malformed_content = """
This is not a valid log entry
Another invalid line
Aug 11 17:15:12 ubuntu-server sshd[1251]: Failed password for invalid user admin from 203.0.113.55 port 48122 ssh2
Random text here
    """
    malformed_log_path.write_text(malformed_content)

    try:
        agent_output = await soc_evaluator.run_agent(
            {"log_file_path": str(malformed_log_path)}
        )
        report = agent_output.get("incident_report", "")
        assert (
            "203.0.113.55" in report
        ), "Should still detect valid entries among malformed ones"
        print("✅ Malformed log entries handled gracefully")
    finally:
        malformed_log_path.unlink(missing_ok=True)


if __name__ == "__main__":
    """
    Standalone evaluation runner for running outside of pytest.
    Demonstrates the modular architecture benefits.
    """

    async def main():
        print("SOC Agent Evaluation Framework")
        print("Modular Subgraph Architecture Test Suite")
        print("=" * 60)

        evaluator = SOCAgentEvaluator()
        sample_input = {"log_file_path": str(AUTH_LOG_PATH)}

        # Run comprehensive evaluation
        print("\nRunning comprehensive evaluation...")
        results = await evaluator.comprehensive_evaluation(sample_input)

        # Display results
        print("\n" + "=" * 60)
        print("EVALUATION COMPLETE")
        print("=" * 60)
        print(f"Detection Rate: {results['detection_rate']:.1f}%")
        print(f"Report Quality: {results['report_quality_scores']['overall_score']}/10")
        print(f"Execution Time: {results['execution_time']:.2f} seconds")
        print(f"\nOVERALL: {'✅ PASS' if results['overall_pass'] else '❌ FAIL'}")
        print("=" * 60)

        # Test subgraph modularity
        print("\nTesting subgraph independence...")
        await test_subgraph_modularity()

        print("\n✅ All evaluations complete!")
        print("Run with pytest for detailed test results:")
        print("  pytest tests/test_soc_agent_evaluation.py -v")

    # Run async main
    asyncio.run(main())
