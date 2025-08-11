"""SOC Analyst Agent using LangGraph and Ollama.

This is a template for building an AI SOC analyst that processes security logs
and generates incident reports using a local Ollama LLM.

NOTE: The challenge mentions building in "/agent directory" but this template
uses "/src/agent" following Python package conventions. Candidates can reorganize
as needed or work within this structure.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, TypedDict

from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph

# Load environment variables
load_dotenv()


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
    log_file_path: str = ""
    
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
    model = configuration.get("ollama_model") or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    base_url = configuration.get("ollama_base_url") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    
    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=0.1,  # Low temperature for consistent analysis
    )


async def parse_logs(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Log Parser: Reads data/auth.log and parses it into a structured format.
    
    TODO: Implement log parsing logic here.
    TODO: Read the file from state.log_file_path (should be "data/auth.log")
    TODO: Parse each line into structured format (timestamp, service, event_type, user, ip, etc.)
    TODO: Handle different log formats and edge cases
    """
    # TODO: Read the actual log file
    # with open(state.log_file_path, 'r') as f:
    #     log_lines = f.readlines()
    
    # TODO: Parse each line using regex or string parsing
    # TODO: Extract: timestamp, hostname, service, pid, event_type, user, ip, port, etc.
    
    # Placeholder implementation showing expected structure
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
            "port": 22
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
            "reason": "invalid_user"
        }
        # TODO: Parse all log entries from data/auth.log
    ]
    
    return {"parsed_logs": parsed_logs}


async def detect_anomalies(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Anomaly Detector: Uses an LLM to identify suspicious events from the structured log data.
    
    TODO: Implement anomaly detection using the Ollama LLM.
    TODO: Analyze state.parsed_logs to identify suspicious patterns
    TODO: Look for brute force attacks, invalid users, unusual login patterns, etc.
    TODO: Return structured suspicious events that can be enriched by the next node
    """
    llm = get_ollama_llm(config)
    
    # Example prompt for anomaly detection
    prompt = f"""
    You are a cybersecurity analyst. Analyze these parsed authentication logs and identify suspicious activities:
    
    Parsed Logs: {state.parsed_logs}
    
    Look for these suspicious patterns:
    - Multiple failed login attempts from the same IP
    - Brute force attack patterns (rapid sequential attempts)
    - Invalid/non-existent user login attempts  
    - Successful logins after multiple failures (potential compromise)
    - Login attempts from known malicious IP ranges
    
    For each suspicious event found, return a JSON object with:
    - source_ip: the suspicious IP address
    - event_type: type of suspicious activity (brute_force, invalid_user, etc.)
    - description: detailed explanation of why this is suspicious
    - severity: HIGH, MEDIUM, or LOW
    - affected_accounts: list of usernames targeted
    
    Return as a JSON array of suspicious events.
    """
    
    # TODO: Implement actual LLM call and JSON parsing
    # response = await llm.ainvoke(prompt)
    # suspicious_events = json.loads(response.content)
    # return {"suspicious_events": suspicious_events}
    
    # Placeholder implementation showing expected structure
    return {
        "suspicious_events": [
            {
                "source_ip": "203.0.113.55",
                "event_type": "brute_force", 
                "description": "Multiple failed login attempts for admin, root, and user accounts followed by successful authentication",
                "severity": "HIGH",
                "affected_accounts": ["admin", "root", "user"],
                "event_count": 7,
                "time_range": "Aug 11 17:15:12 - 17:15:26"
            },
            {
                "source_ip": "192.0.2.147",
                "event_type": "invalid_user",
                "description": "Login attempt for non-existent user 'guest'", 
                "severity": "MEDIUM",
                "affected_accounts": ["guest"],
                "event_count": 1,
                "time_range": "Aug 11 17:30:47"
            }
        ]
    }


def ip_reputation_tool(ip_address: str) -> Dict[str, Any]:
    """IP Reputation Tool: Looks up IP address in mock_api_responses.json.
    
    TODO: Implement this tool to read from data/mock_api_responses.json
    and return threat intelligence data for the given IP address.
    
    Args:
        ip_address: IP address to look up
        
    Returns:
        Dictionary containing threat intelligence data or None if not found
    """
    # TODO: Load and parse data/mock_api_responses.json
    # TODO: Look up the IP address and return the corresponding data
    # TODO: Handle cases where IP is not found
    
    # Placeholder implementation
    mock_data = {
        "203.0.113.55": {
            "abuse_confidence_score": 100,
            "country": "China",
            "threat_type": "brute_force"
        }
    }
    return mock_data.get(ip_address)


async def enrich_indicators(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Enrichment Engine (A Tool-Using Node).
    
    For each suspicious indicator identified, it must use tools to gather external context.
    This node implements tools that read from the provided data/mock_api_responses.json file.
    
    TODO: Implement tool usage for each suspicious IP found in state.suspicious_events
    TODO: Use the ip_reputation_tool to enrich each suspicious IP
    TODO: Store results in enriched_data
    """
    enriched_data = {}
    
    # TODO: Loop through suspicious_events and extract IP addresses
    # TODO: For each IP, call ip_reputation_tool(ip) 
    # TODO: Store the enrichment data
    
    # Placeholder implementation
    for event in state.suspicious_events:
        if "ip" in event:
            ip = event["ip"]
            threat_intel = ip_reputation_tool(ip)
            if threat_intel:
                enriched_data[ip] = threat_intel
    
    return {"enriched_data": enriched_data}


async def generate_report(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Report Generator: Synthesizes all findings into a final, well-structured incident brief in Markdown format.
    
    TODO: Implement report generation using the Ollama LLM.
    TODO: Synthesize findings from suspicious_events and enriched_data
    TODO: Create a structured, actionable incident report for a human analyst
    """
    llm = get_ollama_llm(config)
    
    # Example prompt for report generation
    prompt = f"""
    You are a senior SOC analyst. Generate a structured, actionable incident report for a human analyst based on this analysis:
    
    Suspicious Events Found: {state.suspicious_events}
    Threat Intelligence Data: {state.enriched_data}
    
    The incident brief should include:
    1. Executive Summary (brief overview for management)
    2. Technical Details (specific events and indicators)
    3. Indicators of Compromise (IoCs) - list all malicious IPs, domains, etc.
    4. Threat Assessment (risk level and potential impact)
    5. Recommended Actions (specific, actionable steps)
    
    Format as professional Markdown. Be concise but thorough.
    """
    
    # TODO: Implement actual LLM call and response parsing
    # response = await llm.ainvoke(prompt)
    # return {"incident_report": response.content}
    
    # Placeholder implementation - shows expected structure
    return {
        "incident_report": """# Security Incident Report

## Executive Summary
Multiple brute force attacks detected against SSH services from foreign IP addresses. Immediate action required to prevent account compromise.

## Technical Details
- **Attack Type**: SSH Brute Force
- **Source IPs**: 203.0.113.55 (China), 192.0.2.147 (Russia)  
- **Time Range**: Aug 11 17:15:12 - 17:30:49
- **Targeted Accounts**: admin, root, user, guest
- **Success Rate**: Partial success on 'user' account

## Indicators of Compromise (IoCs)
- IP: 203.0.113.55 (Abuse Score: 100/100)
- IP: 192.0.2.147 (Abuse Score: 95/100)
- Attack Pattern: Sequential failed logins followed by successful authentication

## Threat Assessment
- **Risk Level**: HIGH
- **Confidence**: High (confirmed malicious IPs)
- **Potential Impact**: Account compromise, lateral movement, data exfiltration

## Recommended Actions
1. **IMMEDIATE**: Block IPs 203.0.113.55 and 192.0.2.147 at firewall
2. **URGENT**: Force password reset for 'user' account
3. **24h**: Review all successful logins from these IPs
4. **This week**: Implement SSH key-only authentication
5. **Ongoing**: Enable fail2ban or similar brute force protection
"""
    }


# Define the SOC Analyst graph
graph = (
    StateGraph(SOCState, config_schema=Configuration)
    .add_node("parse_logs", parse_logs)
    .add_node("detect_anomalies", detect_anomalies)  
    .add_node("enrich_indicators", enrich_indicators)
    .add_node("generate_report", generate_report)
    .add_edge("__start__", "parse_logs")
    .add_edge("parse_logs", "detect_anomalies")
    .add_edge("detect_anomalies", "enrich_indicators")
    .add_edge("enrich_indicators", "generate_report")
    .compile(name="SOC Analyst Agent")
)
