# Mini Intrusion Detection System (IDS)

A lightweight, Python-based IDS that analyzes authentication logs to detect common attack patterns.  
This project simulates real-world security monitoring used in enterprise environments.

---

## Features

- Detects brute-force attacks (single IP, multiple failed logins)
- Detects credential stuffing (single user, multiple IPs)
- Classifies alerts by **severity levels**:
  - **LOW**: Suspicious behavior
  - **MEDIUM**: Likely attack
  - **HIGH**: Active or confirmed threat
- Generates alerts to `alerts.log` for further analysis
- Supports multiple detection rules in a single monitoring run

---

## Severity Classification

- **LOW**: Suspicious behavior  
- **MEDIUM**: Likely attack  
- **HIGH**: Active or confirmed threat  

This helps prioritize incidents and simulate real SOC workflow.

---

## Security Concepts Covered

- Log parsing and analysis
- Threat detection and prioritization
- Event correlation
- Intrusion detection system (IDS) logic
- Blue team defensive monitoring
- Severity-based alert classification

---

## Technology Stack

- Python 3
- File handling
- Collections (`defaultdict`)
- Datetime manipulation
- Security monitoring logic

---

## Getting Started

1. Clone the repository:

```bash
git clone https://github.com/oderindeisaiah/mini-ids.git
cd mini-ids
