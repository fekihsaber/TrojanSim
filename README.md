# TrojanSim

**An Educational Trojan Behavior Simulator with Rule-Based Detection and a SOC-Style Dashboard**

TrojanSim is a Python-based cybersecurity educational project designed to simulate Trojan-like behaviors, generate security events, and demonstrate how a rule-based detection system can identify suspicious activity and assign risk scores.

The project combines synthetic event generation, JSONL logging, detection rules, and a graphical dashboard to illustrate a simplified security monitoring and investigation workflow.

> **Disclaimer:** TrojanSim is intended strictly for educational and defensive cybersecurity purposes. It simulates behaviors and records synthetic events; it is not an actual Trojan or malware sample.

## Features

- **Behavior Simulation:** Generates synthetic events representing execution, command-and-control (C2) communication, persistence, and sensitive-data access.
- **Security Event Logging:** Records events in JSON Lines (`.jsonl`) format for structured storage and analysis.
- **Rule-Based Detection:** Evaluates recorded events against predefined detection rules.
- **Risk Scoring:** Assigns risk scores and severity levels to recognized event types.
- **Detection Explanations:** Provides detection reasons and recommended investigation actions.
- **Interactive Dashboard:** Uses Python Tkinter to display security events and their associated detection details.

## Technology Stack

- **Language:** Python
- **GUI:** Tkinter
- **Logging Format:** JSON Lines (JSONL)
- **Detection Method:** Rule-based analysis
- **Version Control:** Git and GitHub

## Project Structure


TrojanSimulator/
├── main.py
├── simulator.py
├── detector.py
├── logger.py
├── dashbord.py
└── logs/
    └── events.jsonl
```

- `main.py` — Main application entry point, depending on the implemented workflow.
- `simulator.py` — Contains functions for simulating Trojan-like behaviors.
- `detector.py` — Applies detection rules and generates a detection report.
- `logger.py` — Records and reads structured security events.
- `dashbord.py` — Provides the graphical monitoring dashboard.
- `logs/events.jsonl` — Stores generated synthetic events.

## Requirements

- Python 3
- Git (optional, for cloning the repository)
- Tkinter, generally included with standard Python installations

The project is designed to use Python's standard library for its core functionality.

## Installation

Clone the repository:

```bash
git clone https://github.com/fekihsaber/TrojanSim.git
cd TrojanSim
```

Verify your Python installation:

```bash
python --version
```

## Usage

### 1. Launch the dashboard

```bash
python dashbord.py
```

### 2. Run the detection report

```bash
python detector.py
```

The detection module analyzes recorded events and displays their event types, severity levels, risk scores, detection explanations, and recommendations.

### 3. Explore the simulation

Use the dashboard's available controls to generate synthetic events and inspect how the detection system processes them.

Generated events are stored in `logs/events.jsonl` for subsequent analysis.

## Detection Methodology

TrojanSim uses predefined rules associated with selected synthetic event types. Each matching rule provides a risk score, severity classification, explanation, and recommendation.

The current scoring values are illustrative and are intended to demonstrate the mechanics of rule-based detection. They are not calibrated threat probabilities or indicators of compromise.

Unknown event types are handled without automatically flagging them under the predefined rules.

## Educational Objectives

This project demonstrates foundational cybersecurity concepts:

- Security event generation and structured event logging
- Rule-based threat detection
- Risk scoring and severity classification
- Investigation-oriented recommendations
- Graphical security monitoring
- Structured security data using JSONL

## Limitations

- All Trojan-like behaviors are simulated.
- The detection engine uses predefined rules rather than machine learning.
- Risk scores are illustrative and should not be interpreted as calibrated probabilities.
- The project is an educational prototype, not a production Security Information and Event Management (SIEM) system.

## Future Improvements

Potential future extensions may include event correlation, configurable rules, improved reporting, and additional detection scenarios.


## Author

**Saber Fekih**

Master's student in Computer Systems and Network Security (MP-SSIR).

GitHub: [@fekihsaber](https://github.com/fekihsaber)

## License

No license has been specified yet. All rights are reserved by default unless a license is added to the repository.

