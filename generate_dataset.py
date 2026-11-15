import json
import os
import random

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


def write_demo(name, data):
    path = os.path.join(OUT, name)
    print(f"wrote {path}")


def make_records(n):
    out = []
    for _ in range(n):
        out.append(
            {
                "account_id": str(random.randint(000_000_000, 999_999_999)),
                "balance": f"${random.uniform(0, 250_000):,.2f}",
                "status": random.choice(STATUSES),
            }
        )
    return json.dumps(out, separators=(",", ":")).encode()


def main(exec):
    exec("phase1_secret_exchange.txt", b"BankSessionSecret2026!#")

    # example = '{\n\t"account_id":"987654321",\n\t"balance":"$5,420.50",\n\t"status":"Active"\n}'

    # The tuple stands for the number of accounts
    for n in (1, 100, 1_000, 10_000):
        exec(f"phase2_balance_{n}.json", make_records(n))


if __name__ == "__main__":
    print("[0] Demo [1] Execute")
    selection = int(input("Select: "))
    if selection == 0:
        main(write_demo)
    elif selection == 1:
        main(write)
    else:
        print("Wrong!")
