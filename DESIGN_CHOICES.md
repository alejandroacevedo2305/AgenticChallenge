# Design Choices & Rationale

This document is the most important part of your submission. It's your opportunity to explain your thought process, the trade-offs you considered, and the reasoning behind your implementation. Clear, concise communication is a critical skill for any engineer, and we're excited to learn how you approached the problem.

---

## 1. Final Agent Architecture

Please provide a high-level overview of your final agentic architecture. You can use a simple text description, a list, or even ASCII art to illustrate the flow of your LangGraph graph. Explain the role of each node and how they connect to one another.

**Example:**

My agent is structured as a stateful graph with the following nodes:

- **`parse_logs`**: This node is the entry point. It takes the `log_file_path` from the SOCState, reads the `data/auth.log` file, and parses each line into structured dictionaries, populating the `parsed_logs` field in the state.

- **`detect_anomalies`**: This node receives the `parsed_logs` from the state and uses the Ollama LLM to identify suspicious patterns. It analyzes the logs for brute force attempts, invalid users, and other anomalies, then updates the `suspicious_events` field.

- **`enrich_indicators`**: This node takes the `suspicious_events` (particularly IP addresses) and enriches them using the mock threat intelligence data from `data/mock_api_responses.json`. It populates the `enriched_data` field with abuse scores, country information, and threat classifications.

- **`generate_report`**: This final node synthesizes all the information from `suspicious_events` and `enriched_data` to create a professional incident report using the LLM, storing the result in the `incident_report` field.

The graph follows a linear flow: `__start__` → `parse_logs` → `detect_anomalies` → `enrich_indicators` → `generate_report`. Each node updates the shared `SOCState` object, allowing information to flow seamlessly between nodes.

---

## 2. Key Technical Decisions & Trade-Offs

This is where you can really shine. Discuss the most significant decisions you made during the project. What alternatives did you consider, and why did you choose your final approach?

### Log Parsing Strategy

- **How did you approach log parsing?** Did you use regular expressions, simple string splitting, or another method? Why? What are the pros and cons of your approach?

### Anomaly Detection Approach

- **How did you design your prompt for the `detect_anomalies` node?** What information did you provide to the LLM? Did you experiment with different prompting techniques (e.g., few-shot, chain-of-thought)?

### State Management Design

- **How did you structure the `SOCState` object?** Our template includes fields like `log_file_path`, `parsed_logs`, `suspicious_events`, `enriched_data`, `incident_report`, and `processing_errors`. What information did you decide to pass between nodes, and why was that important for the overall workflow?
- **Did you modify the state structure?** Did you add additional fields or change the data types? How did you handle the mutable default values in the `__post_init__` method?

### Tool Implementation

- **How did you design your IP reputation tool?** Did you implement it as a simple dictionary lookup using `data/mock_api_responses.json`? How did you handle cases where an IP isn't found in the mock data?
- **What would you need to change to make it a real API call?** Consider authentication, rate limiting, error handling, and response parsing.
- **Did you implement additional tools?** For example, domain reputation, VirusTotal-style analysis, or WHOIS lookups using the mock data?

### Error Handling Strategy

- **How does your agent handle potential errors?** For example, what happens if the `data/auth.log` file is malformed, or if a suspicious IP isn't found in `data/mock_api_responses.json`?
- **How did you use the `processing_errors` field in SOCState?** Did you accumulate errors and continue processing, or fail fast?
- **LLM error handling:** What happens if the Ollama service is down or returns unexpected responses? How do you handle JSON parsing errors from LLM outputs?

### Model Selection & Configuration

- **Why did you choose the `llama3.1:8b` model?** What are the trade-offs of using a local, smaller model versus a larger, cloud-based one?
- **How did you configure the Ollama integration?** Did you use the `get_ollama_llm()` function as-is, or did you modify the temperature, base_url, or other parameters?
- **Prompt engineering choices:** How did you structure your prompts for the `detect_anomalies` and `generate_report` nodes? Did you use system messages, few-shot examples, or specific formatting instructions?

---

## 3. Future Improvements & Next Steps

No project is ever truly "finished." If you had another week to work on this, what would you do next? What would you prioritize, and why?

Consider these areas:

### Accuracy & Intelligence

- How would you improve the accuracy of the anomaly detection?
- What additional context or features would help the LLM make better decisions?

### Tool Expansion

- What other tools would be most valuable to add to the agent's toolkit?
- How would you prioritize which tools to implement first?

### Scalability & Robustness

- How would you make the agent more robust or scalable?
- What changes would be needed to move this from a prototype to a production-ready system?

### Evaluation Framework

- How would you improve your evaluation framework?
- What other metrics would be useful beyond detection rate and report quality?

---

## 4. Challenges Faced & Lessons Learned

What was the hardest part of this challenge for you? How did you overcome it? What did you learn along the way?

This is a great place to talk about:

- A difficult bug you encountered and how you solved it
- A design problem you had to rethink
- A new concept you learned while working on the project
- Trade-offs between different approaches you considered

We value transparency and a growth mindset! Don't be afraid to discuss what didn't work initially and how you iterated to find a better solution.

---

## 5. Evaluation Results & Analysis

### Your Metrics

- **Detection Rate**: What percentage of the known malicious IPs (`203.0.113.55` and `192.0.2.147` from `data/ground_truth.json`) did your agent identify? How does this compare to the 80% target?
- **Report Quality Score**: What was your LLM-as-a-judge score using the evaluation framework in `tests/`? What specific areas (clarity, technical accuracy, actionability, completeness) scored well or poorly?
- **Agent-evals results**: How did your implementation perform on the test cases in `tests/test_soc_agent_evaluation.py`?

### Analysis

- Were there any patterns in what your agent missed or got wrong?
- What do you think are the main factors limiting your agent's performance?
- How would you validate these results in a real-world scenario?
