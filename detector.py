
from logger import read_events


RULES = {
    "SIMULATED_EXECUTION": {
        "score": 30,
        "severity": "WARNING",
        "reason": "Simulated program execution behavior detected.",
        "recommendation": (
            "Review the event context and verify whether the "
            "execution was expected."
        ),
    },
    "SIMULATED_C2": {
        "score": 80,
        "severity": "HIGH",
        "reason": (
            "Simulated command-and-control (C2) communication "
            "behavior detected."
        ),
        "recommendation": (
            "Investigate related network logs and verify whether "
            "the communication is authorized."
        ),
    },
    "SIMULATED_PERSISTENCE": {
        "score": 70,
        "severity": "HIGH",
        "reason": "Simulated persistence behavior detected.",
        "recommendation": (
            "Review startup configuration and persistence-related "
            "events in the lab."
        ),
    },
    "SIMULATED_DATA_ACCESS": {
        "score": 40,
        "severity": "WARNING",
        "reason": "Simulated sensitive-data access behavior detected.",
        "recommendation": (
            "Review the accessed-resource metadata and confirm "
            "whether the activity was authorized."
        ),
    },
}


def analyze_events():
    events = read_events()
    results = []

    for event in events:
        event_type = event.get("event_type", "UNKNOWN")
        rule = RULES.get(event_type)

        if rule is None:
            result = {
                **event,
                "risk_score": 0,
                "severity": "INFO",
                "detection_reason": (
                    "No detection rule matches this event type."
                ),
                "recommendation": (
                    "Review manually if the event appears unusual."
                ),
                "flagged": False,
            }
        else:
            result = {
                **event,
                "risk_score": rule["score"],
                "severity": rule["severity"],
                "detection_reason": rule["reason"],
                "recommendation": rule["recommendation"],
                "flagged": True,
            }

        results.append(result)

    return results


def print_report():
    results = analyze_events()

    print("\n" + "=" * 65)
    print("           TROJANSIM - DETECTION REPORT")
    print("=" * 65)
    print(f"Events analyzed: {len(results)}")
    print(f"Flagged events:  {sum(r['flagged'] for r in results)}")

    for index, event in enumerate(results, start=1):
        print(f"\n--- Event {index} ---")
        print(f"Type:           {event.get('event_type', 'UNKNOWN')}")
        print(f"Severity:       {event['severity']}")
        print(f"Risk score:     {event['risk_score']}/100")
        print(f"Detection reason: {event['detection_reason']}")
        print(f"Recommendation: {event['recommendation']}")

    print("\n" + "=" * 65)


if __name__ == "__main__":
    print_report()
