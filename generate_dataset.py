from datetime import datetime
from datetime import timedelta
import json
import os
import random

OUT: str = "dataset"
os.makedirs(OUT, exist_ok=True)
random.seed(42)  # reproducible

STATUSES: list[str] = ["Active"] * 8 + [
    "Frozen",
    "Closed",
]  # multiply by 8 make 80% of account active


def write(name: str, data: bytes) -> None:
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data):,} bytes)")


def generate_random_date(start_date: datetime, end_date: datetime) -> datetime:
    return start_date + timedelta(
        days=random.randint(0, (end_date - start_date).days)
    )


def generate_record(start_date: datetime, end_date: datetime) -> dict[str, str]:
    return {
        "account_id": str(random.randint(0, 999_999_999)).zfill(9),
        "Date": generate_random_date(start_date, end_date).strftime("%d/%m/%Y"),
        "balance": f"${random.uniform(0, 250_000):,.2f}",
        "status": random.choice(STATUSES),
    }


def generate_dataset(target_bytes: int) -> bytes:
    start_date, end_date = datetime(2000, 1, 1), datetime(2026, 12, 31)
    records: list[str] = []
    size = 0

    while True:
        record = generate_record(start_date, end_date)
        line = json.dumps(record, separators=(",", ":"))
        extra = len(line) + 1
        if size + extra > target_bytes:
            break
        records.append(line)
        size += extra

    data = ("\n".join(records) + "\n").encode("utf-8")
    return data + b" " * (target_bytes - len(data))


def main() -> None:
    write("secret_exchange.txt", b"BankSessionSecret2026!#")

    sizes: dict[str, int] = {
        "1KB": 1024,
        "1MB": 1024**2,
        "10MB": 10 * 1024**2,
        "100MB": 100 * 1024**2,
    }

    for name, n in sizes.items():
        write(f"transaction_{name}.jsonl", generate_dataset(n))


if __name__ == "__main__":
    main()
