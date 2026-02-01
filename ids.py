from collections import defaultdict
from datetime import datetime

LOG_FILE = "sample.log"
ALERT_FILE = "alerts.log"

IP_FAIL_THRESHOLD = 3
USER_IP_THRESHOLD = 3


def parse_log(line: str):
    parts = line.strip().split()
    timestamp = datetime.strptime(
        f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S"
    )
    status = parts[2]
    user = parts[3].split("=")[1]
    ip = parts[4].split("=")[1]

    return timestamp, status, user, ip


def detect_intrusions():
    ip_failures = defaultdict(int)
    user_ips = defaultdict(set)
    alerts = []

    with open(LOG_FILE, "r") as log:
        for line in log:
            timestamp, status, user, ip = parse_log(line)

            if status == "LOGIN_FAIL":
                # Rule 1: Brute-force (MEDIUM → HIGH)
                ip_failures[ip] += 1

                if ip_failures[ip] == IP_FAIL_THRESHOLD:
                    alerts.append(
                        f"[{timestamp}] [MEDIUM] "
                        f"Brute-force suspected from IP {ip}"
                    )

                if ip_failures[ip] >= IP_FAIL_THRESHOLD + 2:
                    alerts.append(
                        f"[{timestamp}] [HIGH] "
                        f"Confirmed brute-force attack from IP {ip}"
                    )

                # Rule 2: Credential stuffing (HIGH)
                user_ips[user].add(ip)

                if len(user_ips[user]) == USER_IP_THRESHOLD:
                    alerts.append(
                        f"[{timestamp}] [HIGH] "
                        f"Credential stuffing detected on user '{user}'"
                    )

    return alerts


def write_alerts(alerts):
    if not alerts:
        print("No intrusions detected.")
        return

    with open(ALERT_FILE, "a") as file:
        for alert in alerts:
            file.write(alert + "\n")

    print(f"{len(alerts)} alert(s) logged with severity levels.")


def main():
    print("=== Mini IDS with Severity Levels ===")
    alerts = detect_intrusions()
    write_alerts(alerts)


if __name__ == "__main__":
    main()
