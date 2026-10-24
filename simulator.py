from logger import log_event


def simulate_execution():
    log_event(
        "SIMULATED_EXECUTION",
        "Simulation : execution d'une application inconnue.",
        "WARNING"
    )


def simulate_c2():
    log_event(
        "SIMULATED_C2",
        "Simulation : communication avec un serveur C2 fictif.",
        "HIGH"
    )


def simulate_persistence():
    log_event(
        "SIMULATED_PERSISTENCE",
        "Simulation : tentative de persistance fictive.",
        "HIGH"
    )


def simulate_data_access():
    log_event(
        "SIMULATED_DATA_ACCESS",
        "Simulation : acces inhabituel aux donnees.",
        "WARNING"
    )