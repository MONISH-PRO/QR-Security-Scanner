import csv
import os
from datetime import datetime

HISTORY_FILE = "scan_history.csv"


def save_scan(qr_content, risk_score, status):

    file_exists = os.path.exists(HISTORY_FILE)

    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Date & Time",
                "QR Content",
                "Risk Score",
                "Status"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            qr_content,
            risk_score,
            status
        ])