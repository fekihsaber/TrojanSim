import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "events.jsonl"


def log_event(event_type, description, severity="INFO"):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "description": description,
        "severity": severity,
        "source": "TrojanSimulator"
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"[{severity}] {description}")


def read_events():
    if not LOG_FILE.exists():
        return []

    events = []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print("[ERREUR] Ligne JSON invalide ignorée.")

    return events