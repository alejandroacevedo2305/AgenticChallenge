"""Detect anomalies in the parsed logs.

use as:
source venv/bin/activate && python src/agent/subgraph_detect_anomalies.py

or

source venv/bin/activate && python -m src.agent.subgraph_detect_anomalies
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List
from typing_extensions import TypedDict

from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langchain_ollama import ChatOllama
from langgraph.graph import START, StateGraph

# Load environment variables
load_dotenv(override=True)


# %%
class Configuration(TypedDict):
    """Configurable parameters for the SOC agent.

    Set these when creating assistants OR when invoking the graph.
    """

    ollama_model: str
    ollama_base_url: str


@dataclass
class SOCState:
    """State for the SOC Analyst Agent.

    This state is passed between nodes and accumulates information
    throughout the analysis process.
    """

    # Input data
    log_file_path: str = "data/auth.log"  # Default to auth.log

    # Processed data
    parsed_logs: List[Dict[str, Any]] = None
    suspicious_events: List[Dict[str, Any]] = None
    enriched_data: Dict[str, Any] = None

    # Final output
    incident_report: str = ""

    # Metadata
    processing_errors: List[str] = None

    def __post_init__(self):
        """Initialize mutable default values."""
        if self.parsed_logs is None:
            self.parsed_logs = []
        if self.suspicious_events is None:
            self.suspicious_events = []
        if self.enriched_data is None:
            self.enriched_data = {}
        if self.processing_errors is None:
            self.processing_errors = []


def get_ollama_llm(config: RunnableConfig) -> ChatOllama:
    """Create and configure Ollama LLM instance.

    Args:
        config: Runtime configuration containing Ollama settings

    Returns:
        Configured ChatOllama instance
    """
    configuration = config.get("configurable", {})

    # Get Ollama settings from config or environment
    model = configuration.get("ollama_model") or os.getenv(
        "OLLAMA_MODEL", "llama3.1:8b"
    )
    base_url = configuration.get("ollama_base_url") or os.getenv(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    )

    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=0.1,  # Low temperature for consistent analysis
    )


async def detect_anomalies(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Anomaly Detector: Uses an LLM to identify suspicious events from the structured log data.

    Analyzes parsed logs to identify suspicious patterns like brute force attacks,
    invalid users, and unusual login patterns.
    """
    llm = get_ollama_llm(config)

    # Construct prompt for anomaly detection
    prompt = f"""You are a cybersecurity analyst. Analyze these parsed authentication logs and identify suspicious activities.

Parsed Logs:
{json.dumps(state.parsed_logs, indent=2)}

Look for these CRITICAL suspicious patterns:
1. **SUCCESSFUL LOGIN AFTER FAILED ATTEMPTS** - This indicates SYSTEM COMPROMISE
2. Multiple failed login attempts from the same IP (brute force)
3. Invalid/non-existent user login attempts
4. Login attempts from known malicious IP ranges
5. Unusual timestamps or patterns

CRITICAL: If you see a successful login from an IP that had previous failed attempts, mark it as:
- event_type: "successful_breach" 
- severity: "CRITICAL"
- Include "SYSTEM COMPROMISED" in the description

For each suspicious event found, create a JSON object with these fields:
- source_ip: the suspicious IP address
- event_type: type of suspicious activity (choose from: successful_breach, brute_force, invalid_user, privilege_escalation, unusual_time, suspicious_pattern)
- description: detailed explanation of why this is suspicious
- severity: CRITICAL, HIGH, MEDIUM, or LOW
- affected_accounts: list of usernames targeted
- event_count: number of related events (optional)
- time_range: time range of the activity (optional)
- compromised: true/false - Set to true if successful login after failures

IMPORTANT: Return ONLY a valid JSON array of suspicious events, nothing else. 
If no suspicious activity is found, return an empty array [].

Example format:
[
  {{
    "source_ip": "192.168.1.100",
    "event_type": "brute_force",
    "description": "Multiple failed login attempts",
    "severity": "HIGH",
    "affected_accounts": ["admin", "root"]
  }}
]
"""

    try:
        # Call the LLM
        response = await llm.ainvoke(prompt)

        # Extract the content
        content = response.content

        # Try to find JSON in the response (in case there's extra text)
        # Look for content between [ and ]
        start_idx = content.find("[")
        end_idx = content.rfind("]")

        if start_idx != -1 and end_idx != -1:
            json_str = content[start_idx : end_idx + 1]
            suspicious_events = json.loads(json_str)
        else:
            # If no JSON array found, try to parse the entire content
            suspicious_events = json.loads(content)

        # Validate that we got a list
        if not isinstance(suspicious_events, list):
            print(
                f"Warning: LLM response was not a list, got: {type(suspicious_events)}"
            )
            suspicious_events = []

    except json.JSONDecodeError as e:
        print(f"Error parsing LLM response as JSON: {e}")
        print(
            f"Raw response: {response.content if 'response' in locals() else 'No response'}"
        )

        # Fallback to a basic analysis based on the logs
        suspicious_events = []

        # Analyze the logs manually for basic patterns
        for log in state.parsed_logs:
            if log.get("event_type") == "failed_login":
                if log.get("reason") == "invalid_user":
                    suspicious_events.append(
                        {
                            "source_ip": log.get("source_ip", "unknown"),
                            "event_type": "invalid_user",
                            "description": f"Login attempt for invalid user '{log.get('user', 'unknown')}'",
                            "severity": "MEDIUM",
                            "affected_accounts": [log.get("user", "unknown")],
                            "time_range": log.get("timestamp", "unknown"),
                        }
                    )

    except Exception as e:
        print(f"Error calling LLM: {e}")
        # Return empty list on error
        suspicious_events = []

    # CRITICAL: Additional manual check for successful breaches
    # This ensures we NEVER miss a successful login after failed attempts
    ip_failed_attempts = {}
    ip_successful_logins = {}

    # First pass: count failed attempts per IP
    for log in state.parsed_logs:
        ip = log.get("source_ip")
        if log.get("event_type") == "failed_login":
            if ip not in ip_failed_attempts:
                ip_failed_attempts[ip] = []
            ip_failed_attempts[ip].append(log)
        elif log.get("event_type") == "successful_login":
            if ip not in ip_successful_logins:
                ip_successful_logins[ip] = []
            ip_successful_logins[ip].append(log)

    # Check for successful breaches (successful login from IP with failed attempts)
    for ip in ip_successful_logins:
        if ip in ip_failed_attempts:
            # CRITICAL: This IP had failures then success = BREACH!
            successful = ip_successful_logins[ip][0]
            compromised_user = successful.get("user")  # The actual compromised account

            # Check if LLM already detected this breach
            breach_detected = False
            for i, event in enumerate(suspicious_events):
                if (
                    event.get("source_ip") == ip
                    and "breach" in event.get("event_type", "").lower()
                ):
                    breach_detected = True
                    # Update the existing event with the correct compromised account
                    if not event.get("compromised_account"):
                        event["compromised_account"] = compromised_user
                        event["description"] = (
                            f"CRITICAL: SYSTEM COMPROMISED! User '{compromised_user}' successfully logged in from {ip} after failed attempts. The attacker has ACTIVE ACCESS to the system."
                        )
                    break

            if not breach_detected:
                # Add critical breach event if not already detected
                failed_count = len(ip_failed_attempts[ip])
                successful = ip_successful_logins[ip][0]
                failed_users = list(
                    set([log.get("user") for log in ip_failed_attempts[ip]])
                )
                compromised_user = successful.get(
                    "user"
                )  # The actual compromised account

                # Build list of ALL targeted accounts (failed attempts + successful)
                all_targeted = failed_users.copy()
                if compromised_user not in all_targeted:
                    all_targeted.append(compromised_user)

                suspicious_events.append(
                    {
                        "source_ip": ip,
                        "event_type": "successful_breach",
                        "description": f"CRITICAL: SYSTEM COMPROMISED! Successful login for user '{compromised_user}' from {ip} after {failed_count} failed attempts. Attacker tried accounts: {', '.join(failed_users)} and SUCCEEDED with account: {compromised_user}",
                        "severity": "CRITICAL",
                        "affected_accounts": all_targeted,  # All accounts that were targeted
                        "event_count": failed_count + 1,
                        "compromised": True,
                        "compromised_account": compromised_user,  # The specific account that was compromised
                        "time_range": f"{ip_failed_attempts[ip][0].get('timestamp')} - {successful.get('timestamp')}",
                    }
                )

    return {"suspicious_events": suspicious_events}


builder = StateGraph(SOCState)
builder.add_node("detect_anomalies", detect_anomalies)
builder.add_edge(START, "detect_anomalies")
subgraph_detect_anomalies = builder.compile()

if __name__ == "__main__":

    parsed_logs = [
        {
            "timestamp": "Aug 11 17:01:01",
            "hostname": "ubuntu-server",
            "service": "sshd",
            "pid": 1101,
            "event_type": "successful_login",
            "auth_method": "publickey",
            "user": "user",
            "source_ip": "198.51.100.12",
            "port": 22,
        },
        {
            "timestamp": "Aug 11 17:15:12",
            "hostname": "ubuntu-server",
            "service": "sshd",
            "pid": 1251,
            "event_type": "failed_login",
            "user": "admin",
            "source_ip": "203.0.113.55",
            "port": 48122,
            "reason": "invalid_user",
        },
    ]

    import asyncio

    async def _main() -> None:
        async for _chunk in subgraph_detect_anomalies.astream(
            {"parsed_logs": parsed_logs},
            stream_mode="updates",
            subgraphs=True,
            debug=True,
        ):
            pass

    asyncio.run(_main())
