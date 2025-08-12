"""
Unit tests for individual subgraphs.

This demonstrates the modularity of the subgraph architecture where
each component can be tested independently.
"""

import pytest
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Any

# Import individual subgraphs
import sys

sys.path.append(str(Path(__file__).parent.parent.parent))
from src.agent.subgraph_parse_logs import subgraph_parse_logs
from src.agent.subgraph_detect_anomalies import subgraph_detect_anomalies
from src.agent.subgraph_enrich_indicators import subgraph_enrich_indicators
from src.agent.subraph_generate_report import subgraph_generate_report


class TestParseLogsSubgraph:
    """Test the parse_logs subgraph in isolation."""

    @pytest.mark.asyncio
    async def test_parse_valid_logs(self):
        """Test parsing of valid SSH log entries."""
        # Create test log content
        test_log = """Aug 11 17:15:12 ubuntu-server sshd[1251]: Failed password for invalid user admin from 203.0.113.55 port 48122 ssh2
Aug 11 17:15:26 ubuntu-server sshd[1251]: Accepted password for user from 203.0.113.55 port 48122 ssh2"""

        # Write to temp file
        test_log_path = Path("/tmp/test_auth.log")
        test_log_path.write_text(test_log)

        # Run subgraph
        state = {"log_file_path": str(test_log_path)}
        result = None

        async for chunk in subgraph_parse_logs.astream(state, stream_mode="updates"):
            for node_name, node_data in chunk.items():
                if "parsed_logs" in node_data:
                    result = node_data["parsed_logs"]

        # Verify results
        assert result is not None, "No parsed logs returned"
        assert len(result) == 2, f"Expected 2 logs, got {len(result)}"

        # Check first log (failed login)
        assert result[0]["event_type"] == "failed_login"
        assert result[0]["source_ip"] == "203.0.113.55"
        assert result[0]["user"] == "admin"

        # Check second log (successful login - CRITICAL for breach detection)
        assert result[1]["event_type"] == "successful_login"
        assert result[1]["source_ip"] == "203.0.113.55"
        assert result[1]["requires_investigation"] == True  # Critical flag!

        # Cleanup
        test_log_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_parse_empty_file(self):
        """Test handling of empty log files."""
        test_log_path = Path("/tmp/empty_auth.log")
        test_log_path.write_text("")

        state = {"log_file_path": str(test_log_path)}
        result = None

        async for chunk in subgraph_parse_logs.astream(state, stream_mode="updates"):
            for node_name, node_data in chunk.items():
                if "parsed_logs" in node_data:
                    result = node_data["parsed_logs"]

        assert result == [], "Should return empty list for empty file"

        test_log_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_parse_malformed_logs(self):
        """Test graceful handling of malformed log entries."""
        test_log = """This is not a valid log
Aug 11 17:15:12 ubuntu-server sshd[1251]: Failed password for invalid user admin from 203.0.113.55 port 48122 ssh2
Another invalid line
Random text"""

        test_log_path = Path("/tmp/malformed_auth.log")
        test_log_path.write_text(test_log)

        state = {"log_file_path": str(test_log_path)}
        result = None

        async for chunk in subgraph_parse_logs.astream(state, stream_mode="updates"):
            for node_name, node_data in chunk.items():
                if "parsed_logs" in node_data:
                    result = node_data["parsed_logs"]

        # Should parse the one valid line
        assert len(result) == 1
        assert result[0]["source_ip"] == "203.0.113.55"

        test_log_path.unlink(missing_ok=True)


class TestDetectAnomaliesSubgraph:
    """Test the detect_anomalies subgraph in isolation."""

    @pytest.mark.asyncio
    async def test_detect_brute_force(self):
        """Test detection of brute force attacks."""
        # Simulated parsed logs with brute force pattern
        parsed_logs = [
            {
                "event_type": "failed_login",
                "source_ip": "203.0.113.55",
                "user": "admin",
                "timestamp": "Aug 11 17:15:12",
            },
            {
                "event_type": "failed_login",
                "source_ip": "203.0.113.55",
                "user": "admin",
                "timestamp": "Aug 11 17:15:14",
            },
            {
                "event_type": "failed_login",
                "source_ip": "203.0.113.55",
                "user": "root",
                "timestamp": "Aug 11 17:15:16",
            },
        ]

        state = {"parsed_logs": parsed_logs}
        result = None

        async for chunk in subgraph_detect_anomalies.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "suspicious_events" in node_data:
                    result = node_data["suspicious_events"]

        assert result is not None, "No suspicious events detected"
        assert len(result) > 0, "Should detect brute force pattern"

        # Check that brute force is detected
        brute_force_detected = any(
            event.get("event_type") in ["brute_force", "multiple_failed_attempts"]
            for event in result
        )
        assert brute_force_detected, "Brute force attack not detected"

    @pytest.mark.asyncio
    async def test_detect_successful_breach(self):
        """Test CRITICAL detection of successful login after failed attempts."""
        # This is the most important test - NEVER miss a breach!
        parsed_logs = [
            {
                "event_type": "failed_login",
                "source_ip": "203.0.113.55",
                "user": "admin",
                "timestamp": "Aug 11 17:15:12",
            },
            {
                "event_type": "failed_login",
                "source_ip": "203.0.113.55",
                "user": "root",
                "timestamp": "Aug 11 17:15:14",
            },
            {
                "event_type": "successful_login",
                "source_ip": "203.0.113.55",
                "user": "user",
                "timestamp": "Aug 11 17:15:26",
            },
        ]

        state = {"parsed_logs": parsed_logs}
        result = None

        async for chunk in subgraph_detect_anomalies.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "suspicious_events" in node_data:
                    result = node_data["suspicious_events"]

        # CRITICAL: Must detect successful breach
        breach_detected = any(
            event.get("event_type") == "successful_breach"
            or event.get("compromised") == True
            for event in result
        )
        assert breach_detected, "CRITICAL FAILURE: Successful breach not detected!"

        # Find the breach event
        breach_event = next(
            (
                e
                for e in result
                if e.get("event_type") == "successful_breach" or e.get("compromised")
            ),
            None,
        )
        assert breach_event is not None
        assert breach_event.get("severity") == "CRITICAL"
        assert breach_event.get("compromised_account") == "user"
        assert "COMPROMISED" in breach_event.get("description", "").upper()

    @pytest.mark.asyncio
    async def test_no_false_positives(self):
        """Test that normal activity doesn't trigger false alarms."""
        # Normal successful logins without failures
        parsed_logs = [
            {
                "event_type": "successful_login",
                "source_ip": "192.168.1.100",
                "user": "user",
                "timestamp": "Aug 11 17:01:01",
            },
            {
                "event_type": "successful_login",
                "source_ip": "192.168.1.101",
                "user": "admin",
                "timestamp": "Aug 11 17:02:01",
            },
        ]

        state = {"parsed_logs": parsed_logs}
        result = None

        async for chunk in subgraph_detect_anomalies.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "suspicious_events" in node_data:
                    result = node_data["suspicious_events"]

        # Should not flag normal logins as breaches
        if result:
            breach_detected = any(
                event.get("event_type") == "successful_breach"
                or event.get("compromised") == True
                for event in result
            )
            assert not breach_detected, "False positive: Normal login flagged as breach"


class TestEnrichIndicatorsSubgraph:
    """Test the enrich_indicators subgraph in isolation."""

    @pytest.mark.asyncio
    async def test_enrich_known_malicious_ip(self):
        """Test enrichment of known malicious IPs."""
        suspicious_events = [
            {
                "source_ip": "203.0.113.55",
                "event_type": "brute_force",
                "severity": "HIGH",
                "affected_accounts": ["admin"],
            }
        ]

        state = {"suspicious_events": suspicious_events}
        result = None

        async for chunk in subgraph_enrich_indicators.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "enriched_data" in node_data:
                    result = node_data["enriched_data"]

        assert result is not None, "No enriched data returned"
        assert "203.0.113.55" in result, "IP not enriched"

        ip_data = result["203.0.113.55"]
        assert "threat_intelligence" in ip_data

        # Check threat level classification
        threat_intel = ip_data["threat_intelligence"]
        if threat_intel.get("abuse_confidence_score", 0) >= 90:
            assert threat_intel.get("threat_level") == "HIGH"

    @pytest.mark.asyncio
    async def test_enrich_with_breach_detection(self):
        """Test that breach events trigger CRITICAL risk classification."""
        suspicious_events = [
            {
                "source_ip": "203.0.113.55",
                "event_type": "successful_breach",
                "severity": "CRITICAL",
                "compromised": True,
                "compromised_account": "user",
                "affected_accounts": ["admin", "root", "user"],
            }
        ]

        state = {"suspicious_events": suspicious_events}
        result = None

        async for chunk in subgraph_enrich_indicators.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "enriched_data" in node_data:
                    result = node_data["enriched_data"]

        ip_data = result["203.0.113.55"]

        # CRITICAL: Breach must result in highest risk classification
        assert ip_data["overall_risk"] == "CRITICAL - SYSTEM COMPROMISED"
        assert ip_data.get("system_compromised") == True
        assert "user" in ip_data.get("compromised_accounts", [])
        assert "ISOLATE" in ip_data.get("action_required", "").upper()

    @pytest.mark.asyncio
    async def test_handle_unknown_ip(self):
        """Test graceful handling of IPs not in threat intelligence."""
        suspicious_events = [
            {
                "source_ip": "10.0.0.1",  # Private IP not in mock data
                "event_type": "failed_login",
                "severity": "LOW",
            }
        ]

        state = {"suspicious_events": suspicious_events}
        result = None

        async for chunk in subgraph_enrich_indicators.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "enriched_data" in node_data:
                    result = node_data["enriched_data"]

        if "10.0.0.1" in result:
            ip_data = result["10.0.0.1"]
            threat_intel = ip_data.get("threat_intelligence", {})
            assert threat_intel.get("status") == "not_found"


class TestGenerateReportSubgraph:
    """Test the generate_report subgraph in isolation."""

    @pytest.mark.asyncio
    async def test_generate_basic_report(self):
        """Test basic report generation."""
        # Minimal state data
        state = {
            "parsed_logs": [
                {"event_type": "failed_login", "source_ip": "203.0.113.55"}
            ],
            "suspicious_events": [
                {
                    "source_ip": "203.0.113.55",
                    "event_type": "brute_force",
                    "severity": "HIGH",
                }
            ],
            "enriched_data": {
                "203.0.113.55": {
                    "threat_intelligence": {"threat_level": "HIGH"},
                    "overall_risk": "HIGH",
                }
            },
        }

        result = None

        async for chunk in subgraph_generate_report.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "incident_report" in node_data:
                    result = node_data["incident_report"]

        assert result is not None, "No report generated"
        assert len(result) > 100, "Report too short"
        assert "203.0.113.55" in result, "IP not mentioned in report"
        assert "HIGH" in result, "Risk level not mentioned"

    @pytest.mark.asyncio
    async def test_report_for_compromised_system(self):
        """Test that compromised systems generate CRITICAL reports."""
        state = {
            "parsed_logs": [],
            "suspicious_events": [
                {
                    "source_ip": "203.0.113.55",
                    "event_type": "successful_breach",
                    "severity": "CRITICAL",
                    "compromised": True,
                    "compromised_account": "admin",
                }
            ],
            "enriched_data": {
                "203.0.113.55": {
                    "overall_risk": "CRITICAL - SYSTEM COMPROMISED",
                    "system_compromised": True,
                    "compromised_accounts": ["admin"],
                }
            },
        }

        result = None

        async for chunk in subgraph_generate_report.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "incident_report" in node_data:
                    result = node_data["incident_report"]

        # CRITICAL: Report must clearly indicate compromise
        assert "COMPROMISED" in result.upper()
        assert "CRITICAL" in result.upper()
        assert "admin" in result
        assert any(
            word in result.upper() for word in ["ISOLATE", "IMMEDIATE", "FORENSIC"]
        )

    @pytest.mark.asyncio
    async def test_fallback_report_generation(self):
        """Test that fallback report works if LLM fails."""
        # Even with minimal/problematic data, report should generate
        state = {"parsed_logs": [], "suspicious_events": [], "enriched_data": {}}

        result = None

        async for chunk in subgraph_generate_report.astream(
            state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "incident_report" in node_data:
                    result = node_data["incident_report"]

        # Should still generate a report (via fallback)
        assert result is not None
        assert "Security Incident Report" in result or "incident" in result.lower()


@pytest.mark.asyncio
async def test_subgraph_independence():
    """
    Verify that each subgraph can run completely independently.
    This is a key benefit of the modular architecture.
    """
    results = {
        "parse_logs": False,
        "detect_anomalies": False,
        "enrich_indicators": False,
        "generate_report": False,
    }

    # Test parse_logs independently
    try:
        test_log = "Aug 11 17:15:12 ubuntu-server sshd[1251]: Failed password for invalid user admin from 203.0.113.55 port 48122 ssh2"
        test_path = Path("/tmp/test_independence.log")
        test_path.write_text(test_log)

        async for chunk in subgraph_parse_logs.astream(
            {"log_file_path": str(test_path)}, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "parsed_logs" in node_data:
                    results["parse_logs"] = True

        test_path.unlink(missing_ok=True)
    except Exception as e:
        print(f"Parse logs failed: {e}")

    # Test detect_anomalies independently
    try:
        test_logs = [
            {"event_type": "failed_login", "source_ip": "1.2.3.4", "user": "test"}
        ]
        async for chunk in subgraph_detect_anomalies.astream(
            {"parsed_logs": test_logs}, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "suspicious_events" in node_data:
                    results["detect_anomalies"] = True
    except Exception as e:
        print(f"Detect anomalies failed: {e}")

    # Test enrich_indicators independently
    try:
        test_events = [{"source_ip": "203.0.113.55", "event_type": "test"}]
        async for chunk in subgraph_enrich_indicators.astream(
            {"suspicious_events": test_events}, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "enriched_data" in node_data:
                    results["enrich_indicators"] = True
    except Exception as e:
        print(f"Enrich indicators failed: {e}")

    # Test generate_report independently
    try:
        test_state = {
            "parsed_logs": [],
            "suspicious_events": [{"source_ip": "1.2.3.4", "event_type": "test"}],
            "enriched_data": {"1.2.3.4": {"overall_risk": "LOW"}},
        }
        async for chunk in subgraph_generate_report.astream(
            test_state, stream_mode="updates"
        ):
            for node_name, node_data in chunk.items():
                if "incident_report" in node_data:
                    results["generate_report"] = True
    except Exception as e:
        print(f"Generate report failed: {e}")

    # All subgraphs should run independently
    assert all(
        results.values()
    ), f"Some subgraphs failed to run independently: {results}"
    print("✅ All subgraphs can run independently - modular architecture validated!")


if __name__ == "__main__":
    """Run unit tests standalone."""
    import sys

    async def main():
        print("Unit Tests for Modular Subgraph Architecture")
        print("=" * 60)

        # Test each subgraph
        print("\n1. Testing Parse Logs Subgraph...")
        test_parse = TestParseLogsSubgraph()
        await test_parse.test_parse_valid_logs()
        print("   ✅ Valid log parsing")
        await test_parse.test_parse_empty_file()
        print("   ✅ Empty file handling")
        await test_parse.test_parse_malformed_logs()
        print("   ✅ Malformed log handling")

        print("\n2. Testing Detect Anomalies Subgraph...")
        test_detect = TestDetectAnomaliesSubgraph()
        await test_detect.test_detect_brute_force()
        print("   ✅ Brute force detection")
        await test_detect.test_detect_successful_breach()
        print("   ✅ CRITICAL: Breach detection working!")
        await test_detect.test_no_false_positives()
        print("   ✅ No false positives")

        print("\n3. Testing Enrich Indicators Subgraph...")
        test_enrich = TestEnrichIndicatorsSubgraph()
        await test_enrich.test_enrich_known_malicious_ip()
        print("   ✅ Known malicious IP enrichment")
        await test_enrich.test_enrich_with_breach_detection()
        print("   ✅ Breach risk classification")
        await test_enrich.test_handle_unknown_ip()
        print("   ✅ Unknown IP handling")

        print("\n4. Testing Generate Report Subgraph...")
        test_report = TestGenerateReportSubgraph()
        await test_report.test_generate_basic_report()
        print("   ✅ Basic report generation")
        await test_report.test_report_for_compromised_system()
        print("   ✅ Compromised system reporting")
        await test_report.test_fallback_report_generation()
        print("   ✅ Fallback report generation")

        print("\n5. Testing Subgraph Independence...")
        await test_subgraph_independence()

        print("\n" + "=" * 60)
        print("✅ All unit tests passed!")
        print("The modular subgraph architecture is working perfectly!")
        print("\nRun with pytest for detailed results:")
        print("  pytest tests/unit_tests/test_subgraphs.py -v")

    asyncio.run(main())
