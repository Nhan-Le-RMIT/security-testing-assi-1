import json
import os
import random
from datetime import datetime, timedelta

OUT = "dataset"
os.makedirs(OUT, exist_ok=True)
random.seed(42)  # reproducible

STATUSES = ["Active"] * 8 + [
    "Frozen",
    "Closed",
]  # multiply by 8 make 80% of account active


def write(name, data):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data):,} bytes)")


def generate_random_date(start_date, end_date):
    return start_date + timedelta(days=random.randint(0, (end_date - start_date).days))


def generate_record(start_date, end_date):
    return {
        "account_id": str(random.randint(0, 999_999_999)).zfill(9),
        "Date": generate_random_date(start_date, end_date).strftime("%d/%m/%Y"),
        "balance": f"${random.uniform(0, 250_000):,.2f}",
        "status": random.choice(STATUSES),
    }


def generate_dataset(target_bytes):
    start_date, end_date = datetime(2000, 1, 1), datetime(2026, 12, 31)
    parts, size = [], 2
    while True:
        item = json.dumps(generate_record(start_date, end_date), separators=(",", ":"))
        extra = len(item) + (1 if parts else 0)
        if size + extra > target_bytes:
            break
        parts.append(item)
        size += extra
    data = ("[" + ",".join(parts) + "]").encode("utf-8")
    return data + b" " * (target_bytes - len(data))


def main():
    write("secret_exchange.txt", b"BankSessionSecret2026!#")

    sizes = {"1KB": 1024, "1MB": 1024**2, "10MB": 10 * 1024**2}

    for name, n in sizes.items():
        write(f"transaction_{name}.json", generate_dataset(n))


if __name__ == "__main__":
    main()
