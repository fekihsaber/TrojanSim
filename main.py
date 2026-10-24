
from simulator import (
    simulate_execution,
    simulate_c2,
    simulate_persistence,
    simulate_data_access,
)
from detector import analyze_events


def display_menu():
    print("\n" + "=" * 50)
    print("     TROJAN SIMULATOR - LABORATOIRE BLUE TEAM")
    print("=" * 50)
    print("1. Simuler une exécution suspecte")
    print("2. Simuler une communication C2")
    print("3. Simuler une tentative de persistance")
    print("4. Simuler un accès inhabituel aux données")
    print("5. Analyser les événements")
    print("6. Quitter")
    print("=" * 50)


def main():
    actions = {
        "1": simulate_execution,
        "2": simulate_c2,
        "3": simulate_persistence,
        "4": simulate_data_access,
        "5": analyze_events,
    }

    while True:
        display_menu()
        choice = input("Votre choix : ").strip()

        if choice == "6":
            print("Fin du laboratoire.")
            break

        action = actions.get(choice)

        if action:
            action()
        else:
            print("Choix invalide. Essayez de nouveau.")


if __name__ == "__main__":
    main()
