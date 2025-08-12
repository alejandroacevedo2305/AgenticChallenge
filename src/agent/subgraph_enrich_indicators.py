"""Enrich indicators with threat intelligence data.

use as:
source venv/bin/activate && python src/agent/subgraph_enrich_indicators.py

or

source venv/bin/activate && python -m src.agent.subgraph_enrich_indicators
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List
from typing_extensions import TypedDict

from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph
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


def ip_reputation_tool(ip_address: str) -> Dict[str, Any]:
    """IP Reputation Tool: Looks up IP address in mock_api_responses.json.

    Reads threat intelligence data from the mock API responses file
    and returns enrichment data for the given IP address.

    Args:
        ip_address: IP address to look up

    Returns:
        Dictionary containing threat intelligence data or None if not found
    """
    import json
    import os

    # Construct path to mock_api_responses.json
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_file = os.path.join(current_dir, "..", "..", "data", "mock_api_responses.json")

    try:
        # Load and parse the JSON file
        with open(data_file, "r", encoding="utf-8") as f:
            mock_data = json.load(f)

        # Look up the IP address
        if ip_address in mock_data:
            ip_data = mock_data[ip_address]

            # Extract relevant threat intelligence fields
            threat_intel = {
                "ip_address": ip_data.get("ip_address", ip_address),
                "abuse_confidence_score": ip_data.get("abuse_confidence_score", 0),
                "country_code": ip_data.get("country_code", "Unknown"),
                "country_name": ip_data.get("country_name", "Unknown"),
                "isp": ip_data.get("isp", "Unknown"),
                "domain": ip_data.get("domain", "Unknown"),
                "total_reports": ip_data.get("total_reports", 0),
                "num_distinct_users": ip_data.get("num_distinct_users", 0),
                "last_reported_at": ip_data.get("last_reported_at", "Unknown"),
                "hostnames": ip_data.get("hostnames", []),
                "reports": ip_data.get("reports", []),
            }

            # Add threat classification based on abuse score
            if threat_intel["abuse_confidence_score"] >= 90:
                threat_intel["threat_level"] = "HIGH"
                threat_intel["recommendation"] = "Block immediately"
            elif threat_intel["abuse_confidence_score"] >= 50:
                threat_intel["threat_level"] = "MEDIUM"
                threat_intel["recommendation"] = "Monitor closely"
            else:
                threat_intel["threat_level"] = "LOW"
                threat_intel["recommendation"] = "Log and review"

            return threat_intel
        else:
            # IP not found in mock data
            return {
                "ip_address": ip_address,
                "status": "not_found",
                "message": f"No threat intelligence data available for IP {ip_address}",
            }

    except FileNotFoundError:
        print(f"Error: Could not find mock_api_responses.json at {data_file}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in ip_reputation_tool: {e}")
        return None


async def enrich_indicators(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Enrichment Engine (A Tool-Using Node).

    For each suspicious indicator identified, it must use tools to gather external context.
    This node implements tools that read from the provided data/mock_api_responses.json file.

    Enriches suspicious IPs with threat intelligence data including:
    - Abuse confidence scores
    - Geographic location
    - ISP information
    - Previous reports
    - Threat level classification
    """
    enriched_data = {}
    processed_ips = set()  # Track already processed IPs to avoid duplicates

    # Loop through suspicious_events and extract IP addresses
    for event in state.suspicious_events:
        # Extract IP from the event (field is "source_ip")
        if "source_ip" in event:
            ip = event["source_ip"]

            # Skip if we've already processed this IP
            if ip in processed_ips:
                continue

            processed_ips.add(ip)

            # Call the IP reputation tool to get threat intelligence
            print(f"Enriching IP: {ip}")
            threat_intel = ip_reputation_tool(ip)

            if threat_intel:
                # Store the enrichment data with additional context from the event
                enriched_data[ip] = {
                    "threat_intelligence": threat_intel,
                    "related_events": [],
                    "first_seen": None,
                    "last_seen": None,
                    "total_suspicious_events": 0,
                }

                # Add context from all events related to this IP
                for evt in state.suspicious_events:
                    if evt.get("source_ip") == ip:
                        enriched_data[ip]["related_events"].append(
                            {
                                "event_type": evt.get("event_type"),
                                "severity": evt.get("severity"),
                                "description": evt.get("description"),
                                "affected_accounts": evt.get("affected_accounts", []),
                                "time_range": evt.get("time_range", "Unknown"),
                            }
                        )
                        enriched_data[ip]["total_suspicious_events"] += 1

                        # Track time range
                        time_range = evt.get("time_range", "")
                        if time_range:
                            if not enriched_data[ip]["first_seen"]:
                                enriched_data[ip]["first_seen"] = time_range
                            enriched_data[ip]["last_seen"] = time_range

                # Check if this IP has any successful breaches
                has_breach = False
                compromised_accounts = []
                for evt in state.suspicious_events:
                    if evt.get("source_ip") == ip and (
                        evt.get("event_type") == "successful_breach"
                        or evt.get("compromised")
                    ):
                        has_breach = True
                        # Get the specific compromised account
                        if evt.get("compromised_account"):
                            compromised_accounts.append(evt.get("compromised_account"))

                # Add summary recommendation based on combined threat data
                if has_breach:
                    # CRITICAL: System has been compromised!
                    enriched_data[ip]["overall_risk"] = "CRITICAL - SYSTEM COMPROMISED"
                    enriched_data[ip]["system_compromised"] = True
                    enriched_data[ip]["compromised_accounts"] = list(
                        set(compromised_accounts)
                    )
                    enriched_data[ip]["action_required"] = (
                        "IMMEDIATE ACTION REQUIRED: "
                        "1) ISOLATE affected system immediately, "
                        "2) RESET all compromised account passwords, "
                        "3) AUDIT all activity from compromised accounts, "
                        "4) CHECK for backdoors/persistence mechanisms, "
                        "5) INITIATE full incident response protocol"
                    )
                elif (
                    threat_intel.get("threat_level") == "HIGH"
                    or enriched_data[ip]["total_suspicious_events"] > 5
                ):
                    enriched_data[ip]["overall_risk"] = "CRITICAL"
                    enriched_data[ip][
                        "action_required"
                    ] = "Immediate blocking and investigation required"
                elif (
                    threat_intel.get("threat_level") == "MEDIUM"
                    or enriched_data[ip]["total_suspicious_events"] > 2
                ):
                    enriched_data[ip]["overall_risk"] = "HIGH"
                    enriched_data[ip][
                        "action_required"
                    ] = "Enhanced monitoring and potential blocking"
                else:
                    enriched_data[ip]["overall_risk"] = "MEDIUM"
                    enriched_data[ip]["action_required"] = "Continue monitoring"
            else:
                print(f"No threat intelligence data available for IP: {ip}")

    # Add summary statistics
    if enriched_data:
        print(f"Enriched {len(enriched_data)} unique IP addresses")
        high_risk_ips = [
            ip
            for ip, data in enriched_data.items()
            if data.get("overall_risk") in ["CRITICAL", "HIGH"]
        ]
        if high_risk_ips:
            print(f"High risk IPs identified: {', '.join(high_risk_ips)}")

    return {"enriched_data": enriched_data}


builder = StateGraph(SOCState)
builder.add_node("enrich_indicators", enrich_indicators)
builder.add_edge(START, "enrich_indicators")
subgraph_enrich_indicators = builder.compile()

if __name__ == "__main__":

    # Use the suspicious events from the detect_anomalies output
    suspicious_events = [
        {
            "source_ip": "203.0.113.55",
            "event_type": "brute_force",
            "description": "Multiple failed login attempts from the same IP within a short time frame",
            "severity": "HIGH",
            "affected_accounts": ["admin"],
            "event_count": 1,
            "time_range": "Aug 11 17:15:12 - Aug 11 17:15:12",
        },
        {
            "source_ip": "203.0.113.55",
            "event_type": "invalid_user",
            "description": "Invalid user login attempt from the same IP as previous brute force attack",
            "severity": "MEDIUM",
            "affected_accounts": ["admin"],
            "time_range": "Aug 11 17:15:12",
        },
        {
            "source_ip": "198.51.100.12",
            "event_type": "successful_login",
            "description": "Successful login but from an IP with no reputation data",
            "severity": "LOW",
            "affected_accounts": ["user"],
            "time_range": "Aug 11 17:01:01",
        },
    ]

    import asyncio

    async def _main() -> None:
        async for _chunk in subgraph_enrich_indicators.astream(
            {"suspicious_events": suspicious_events},
            stream_mode="updates",
            subgraphs=True,
            debug=True,
        ):
            pass

    asyncio.run(_main())
