"""Generate comprehensive security incident reports.

use as:
source venv/bin/activate && python src/agent/subraph_generate_report.py

or

source venv/bin/activate && python -m src.agent.subraph_generate_report
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List
from typing_extensions import TypedDict

from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langchain_ollama import ChatOllama
from langgraph.graph import START, StateGraph

# Load environment variables
load_dotenv(override=True)


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


def format_ioc_list(enriched_data: Dict[str, Any]) -> str:
    """Format Indicators of Compromise from enriched data.

    Args:
        enriched_data: Dictionary containing enriched threat intelligence

    Returns:
        Formatted IoC list as string
    """
    iocs = []

    for ip, data in enriched_data.items():
        threat_intel = data.get("threat_intelligence", {})

        # Format IP with threat level
        threat_level = threat_intel.get("threat_level", "UNKNOWN")
        abuse_score = threat_intel.get("abuse_confidence_score", "N/A")
        country = threat_intel.get("country_name", "Unknown")
        isp = threat_intel.get("isp", "Unknown")

        ioc_entry = f"- **IP: {ip}**\n"
        ioc_entry += f"  - Threat Level: {threat_level}\n"
        ioc_entry += f"  - Abuse Score: {abuse_score}/100\n"
        ioc_entry += f"  - Country: {country}\n"
        ioc_entry += f"  - ISP: {isp}\n"

        # Add hostnames if available
        hostnames = threat_intel.get("hostnames", [])
        if hostnames:
            ioc_entry += f"  - Hostnames: {', '.join(hostnames)}\n"

        iocs.append(ioc_entry)

    return "\n".join(iocs) if iocs else "- No specific IoCs identified"


def calculate_overall_risk(suspicious_events: List[Dict], enriched_data: Dict) -> str:
    """Calculate overall risk level based on events and threat intelligence.

    Args:
        suspicious_events: List of detected suspicious events
        enriched_data: Dictionary containing enriched threat intelligence

    Returns:
        Risk level string (CRITICAL - SYSTEM COMPROMISED, CRITICAL, HIGH, MEDIUM, LOW)
    """
    # CRITICAL CHECK: Is the system compromised?
    for event in suspicious_events:
        if event.get("event_type") == "successful_breach" or event.get("compromised"):
            return "CRITICAL - SYSTEM COMPROMISED"

    # Check enriched data for system compromise
    for ip, data in enriched_data.items():
        if data.get("system_compromised") or "COMPROMISED" in data.get(
            "overall_risk", ""
        ):
            return "CRITICAL - SYSTEM COMPROMISED"

    # Count high severity events
    high_severity_count = sum(
        1
        for event in suspicious_events
        if event.get("severity") in ["HIGH", "CRITICAL"]
    )

    # Check for critical risk IPs
    critical_ips = [
        ip
        for ip, data in enriched_data.items()
        if "CRITICAL" in data.get("overall_risk", "")
    ]

    if critical_ips or high_severity_count >= 2:
        return "CRITICAL"
    elif high_severity_count >= 1 or any(
        data.get("overall_risk") == "HIGH" for data in enriched_data.values()
    ):
        return "HIGH"
    elif len(suspicious_events) > 2:
        return "MEDIUM"
    else:
        return "LOW"


async def generate_report(state: SOCState, config: RunnableConfig) -> Dict[str, Any]:
    """The Report Generator: Synthesizes all findings into a final, well-structured incident brief.

    Generates a comprehensive security incident report that includes:
    - Executive summary for management
    - Technical analysis of detected threats
    - Indicators of Compromise (IoCs)
    - Risk assessment
    - Actionable recommendations
    """
    llm = get_ollama_llm(config)

    # Calculate summary statistics
    total_events = len(state.suspicious_events)
    unique_ips = len(state.enriched_data)
    overall_risk = calculate_overall_risk(state.suspicious_events, state.enriched_data)

    # Format IoCs
    ioc_list = format_ioc_list(state.enriched_data)

    # Get affected accounts
    affected_accounts = set()
    for event in state.suspicious_events:
        accounts = event.get("affected_accounts", [])
        affected_accounts.update(accounts)

    # Check if system is compromised
    system_compromised = "COMPROMISED" in overall_risk
    compromised_accounts = []
    successful_breach_details = None

    for event in state.suspicious_events:
        if event.get("compromised") or event.get("event_type") == "successful_breach":
            successful_breach_details = event
            if event.get("compromised_account"):
                compromised_accounts.append(event.get("compromised_account"))
            # Also extract from affected_accounts if it's the compromised event
            elif event.get("compromised") and event.get("affected_accounts"):
                # The last account in affected_accounts might be the successful one
                compromised_accounts.extend(event.get("affected_accounts", []))

    # Build the prompt with structured data
    prompt = f"""You are a senior SOC analyst. Generate a professional, structured incident report based on this security analysis.

{"⚠️ CRITICAL ALERT: SYSTEM HAS BEEN COMPROMISED! ⚠️" if system_compromised else ""}
{f"Compromised Accounts: {', '.join(compromised_accounts)}" if compromised_accounts else ""}

DETECTED SUSPICIOUS EVENTS:
{json.dumps(state.suspicious_events, indent=2)}

THREAT INTELLIGENCE DATA:
{json.dumps(state.enriched_data, indent=2)}

SUMMARY STATISTICS:
- Total Suspicious Events: {total_events}
- Unique Source IPs: {unique_ips}
- Overall Risk Level: {overall_risk}
- System Status: {"COMPROMISED - IMMEDIATE ACTION REQUIRED" if system_compromised else "Under Attack"}
- Affected Accounts: {', '.join(sorted(affected_accounts)) if affected_accounts else 'None'}
{"- COMPROMISED ACCOUNTS: " + ', '.join(compromised_accounts) if compromised_accounts else ""}

{"CRITICAL: The attacker successfully logged in after brute force attempts. The system is COMPROMISED and the attacker has ACTIVE ACCESS." if system_compromised else ""}

Generate a comprehensive incident report with these sections:

1. **Executive Summary** (2-3 sentences for management)
   - Brief overview of the incident
   - Business impact and urgency
   
2. **Incident Timeline**
   - Key events in chronological order
   - Attack progression
   
3. **Technical Analysis**
   - Attack vectors identified
   - Techniques used by attackers
   - Success/failure of attempts
   
4. **Threat Intelligence Summary**
   - Known malicious IPs and their reputation
   - Geographic origins
   - Previous attack history
   
5. **Risk Assessment**
   - Current risk level and justification
   - Potential impact if not addressed
   - Likelihood of escalation
   
6. **Recommended Actions**
   - Immediate actions (within 1 hour)
   - Short-term actions (within 24 hours)
   - Long-term improvements (within 1 week)

{"CRITICAL INSTRUCTIONS: The report MUST clearly state that:" if system_compromised else ""}
{"1. The attacker SUCCESSFULLY logged in and has ACTIVE ACCESS to the system" if system_compromised else ""}
{"2. The system is CURRENTLY COMPROMISED, not just under attack" if system_compromised else ""}
{"3. The account '" + compromised_accounts[0] + "' was successfully breached after brute force attempts" if system_compromised and compromised_accounts else ""}
{"4. This is NOT just failed attempts - the attacker SUCCEEDED and is IN THE SYSTEM" if system_compromised else ""}
{"5. Include FORENSIC and ISOLATION steps as TOP PRIORITY" if system_compromised else ""}

Format as professional Markdown. Be specific, actionable, and prioritize recommendations by urgency.
Include specific IP addresses, account names, and timestamps where relevant.
NEVER downplay a successful breach as just 'failed attempts' - be clear about successful compromises.
"""

    try:
        # Call the LLM to generate the report
        response = await llm.ainvoke(prompt)
        report_content = response.content

        # Add header with generation timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        final_report = f"""# Security Incident Report
**Generated**: {timestamp}
**Risk Level**: {overall_risk}
**Status**: Active Investigation

---

{report_content}

---

## Indicators of Compromise (IoCs)

{ioc_list}

## Metadata
- Total Log Entries Analyzed: {len(state.parsed_logs)}
- Suspicious Events Detected: {total_events}
- Unique Threat Actors: {unique_ips}
- Analysis Engine: AI-Powered SOC Agent v1.0
"""

        print(f"Report generated successfully - Risk Level: {overall_risk}")

    except Exception as e:
        print(f"Error generating report with LLM: {e}")

        # Fallback to template-based report
        final_report = generate_fallback_report(
            state, overall_risk, total_events, unique_ips, affected_accounts, ioc_list
        )

    return {"incident_report": final_report}


def generate_fallback_report(
    state: SOCState,
    overall_risk: str,
    total_events: int,
    unique_ips: int,
    affected_accounts: set,
    ioc_list: str,
) -> str:
    """Generate a fallback report if LLM fails.

    Args:
        state: Current SOC state
        overall_risk: Calculated risk level
        total_events: Number of suspicious events
        unique_ips: Number of unique IPs
        affected_accounts: Set of affected account names
        ioc_list: Formatted IoC list

    Returns:
        Formatted incident report as string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build event summary
    event_summary = []
    for event in state.suspicious_events:
        event_summary.append(
            f"- {event.get('event_type', 'Unknown')}: {event.get('description', 'No description')}"
        )

    # Check if system is compromised
    system_compromised = "COMPROMISED" in overall_risk

    # Build recommendations based on risk
    if system_compromised:
        immediate_actions = [
            "1. **CRITICAL - ISOLATE SYSTEM NOW**: Disconnect affected system from network immediately",
            "2. **CRITICAL - DISABLE ACCOUNTS**: Disable ALL compromised accounts immediately",
            "3. **CRITICAL - FORENSICS**: Capture memory dump and disk image for forensic analysis",
            "4. **CRITICAL - AUDIT**: Review all activity from compromised accounts since breach",
            "5. **CRITICAL - SCAN**: Check for backdoors, rootkits, and persistence mechanisms",
            "6. **CRITICAL - RESET**: Force password reset for ALL accounts on affected system",
        ]
    elif overall_risk == "CRITICAL":
        immediate_actions = [
            "1. **IMMEDIATE**: Block all identified malicious IPs at the firewall",
            "2. **IMMEDIATE**: Disable affected accounts pending investigation",
            "3. **IMMEDIATE**: Initiate incident response protocol",
        ]
    elif overall_risk == "HIGH":
        immediate_actions = [
            "1. **URGENT**: Block identified malicious IPs",
            "2. **URGENT**: Force password reset for affected accounts",
            "3. **URGENT**: Review all recent authentication logs",
        ]
    else:
        immediate_actions = [
            "1. Monitor identified IPs for further activity",
            "2. Review account security settings",
            "3. Consider implementing additional monitoring",
        ]

    # Check for compromised accounts
    compromised_accounts_list = []
    for event in state.suspicious_events:
        if event.get("compromised_account"):
            compromised_accounts_list.append(event.get("compromised_account"))

    return f"""# {"⚠️ CRITICAL SECURITY BREACH ⚠️" if system_compromised else "Security Incident Report"}
**Generated**: {timestamp}
**Risk Level**: {overall_risk}
**Status**: {"SYSTEM COMPROMISED - ACTIVE BREACH" if system_compromised else "Active Investigation"}
{f"**⚠️ COMPROMISED ACCOUNTS: {', '.join(compromised_accounts_list)} ⚠️**" if compromised_accounts_list else ""}

---

## {"⚠️ CRITICAL: SYSTEM BREACH DETECTED ⚠️" if system_compromised else "Executive Summary"}

{"⚠️ **CRITICAL BREACH**: The attacker has SUCCESSFULLY COMPROMISED the system after brute-force attempts. They have ACTIVE ACCESS through the account(s): " + ', '.join(compromised_accounts_list) + ". IMMEDIATE ISOLATION AND FORENSIC RESPONSE REQUIRED!" if system_compromised else f"Security monitoring has detected {total_events} suspicious event(s) from {unique_ips} unique IP address(es). The incident has been classified as {overall_risk} risk and requires immediate attention from the security team."}

## Technical Details

### Detected Events
{chr(10).join(event_summary) if event_summary else "No specific events detailed"}

### Affected Resources
- **Accounts**: {', '.join(sorted(affected_accounts)) if affected_accounts else 'None identified'}
- **Services**: SSH (port 22)
- **Time Range**: See individual events for specific timestamps

## Threat Assessment

- **Risk Level**: {overall_risk}
- **Confidence**: High (based on threat intelligence correlation)
- **Attack Vector**: Remote authentication attempts
- **Potential Impact**: Account compromise, unauthorized access, data exfiltration

## Indicators of Compromise (IoCs)

{ioc_list}

## Recommended Actions

### Immediate Actions (Within 1 Hour)
{chr(10).join(immediate_actions)}

### Short-term Actions (Within 24 Hours)
1. Conduct forensic analysis of affected systems
2. Review all successful authentications from suspicious IPs
3. Update security monitoring rules

### Long-term Improvements (Within 1 Week)
1. Implement multi-factor authentication (MFA)
2. Deploy intrusion prevention system (IPS)
3. Enhance log monitoring and alerting
4. Review and update incident response procedures

---

## Metadata
- Total Log Entries Analyzed: {len(state.parsed_logs)}
- Suspicious Events Detected: {total_events}
- Unique Threat Actors: {unique_ips}
- Analysis Engine: AI-Powered SOC Agent v1.0 (Fallback Mode)
"""


builder = StateGraph(SOCState)
builder.add_node("generate_report", generate_report)
builder.add_edge(START, "generate_report")
subgraph_generate_report = builder.compile()

if __name__ == "__main__":
    # Sample data matching the output from previous stages
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

    # Sample enriched data from the enrich_indicators stage
    enriched_data = {
        "203.0.113.55": {
            "threat_intelligence": {
                "ip_address": "203.0.113.55",
                "abuse_confidence_score": 100,
                "country_code": "CN",
                "country_name": "China",
                "isp": "China Telecom",
                "domain": "chinatelecom.com.cn",
                "total_reports": 582,
                "num_distinct_users": 150,
                "last_reported_at": "2023-08-11T12:00:00+00:00",
                "hostnames": [],
                "threat_level": "HIGH",
                "recommendation": "Block immediately",
            },
            "related_events": [
                {
                    "event_type": "brute_force",
                    "severity": "HIGH",
                    "description": "Multiple failed login attempts",
                    "affected_accounts": ["admin"],
                    "time_range": "Aug 11 17:15:12 - Aug 11 17:15:12",
                },
                {
                    "event_type": "invalid_user",
                    "severity": "MEDIUM",
                    "description": "Invalid user login attempt",
                    "affected_accounts": ["admin"],
                    "time_range": "Aug 11 17:15:12",
                },
            ],
            "first_seen": "Aug 11 17:15:12 - Aug 11 17:15:12",
            "last_seen": "Aug 11 17:15:12",
            "total_suspicious_events": 2,
            "overall_risk": "CRITICAL",
            "action_required": "Immediate blocking and investigation required",
        },
        "198.51.100.12": {
            "threat_intelligence": {
                "ip_address": "198.51.100.12",
                "status": "not_found",
                "message": "No threat intelligence data available for IP 198.51.100.12",
            },
            "related_events": [
                {
                    "event_type": "successful_login",
                    "severity": "LOW",
                    "description": "Successful login",
                    "affected_accounts": ["user"],
                    "time_range": "Aug 11 17:01:01",
                }
            ],
            "first_seen": "Aug 11 17:01:01",
            "last_seen": "Aug 11 17:01:01",
            "total_suspicious_events": 1,
            "overall_risk": "MEDIUM",
            "action_required": "Continue monitoring",
        },
    }

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
        async for _chunk in subgraph_generate_report.astream(
            {
                "parsed_logs": parsed_logs,
                "suspicious_events": suspicious_events,
                "enriched_data": enriched_data,
            },
            stream_mode="updates",
            subgraphs=True,
            debug=True,
        ):
            pass

    asyncio.run(_main())
