import os
import random
import secrets

FLAG = os.getenv("FLAG")
rng = random.Random(secrets.randbits(64))


print("=== The Future? ===")
print("A small oracle hums... it only speaks in 32-bit prophecies.")
print("Menu: [1] consult the present  [2] name the future  [3] leave quietly")

pos = 0
while True:
    choice = input("> ").strip()
    if choice == "1":
        print(f"[present #{pos:03d}] {rng.getrandbits(32)}")
        pos += 1
    elif choice == "2":
        i = secrets.randbelow(128)
        for _ in range(i):
            rng.getrandbits(32)
        ans = rng.getrandbits(32)
        print(f"The oracle points to the timeline: i = {i}")
        try:
            guess = int(input("Speak the next omen > ").strip(), 0)
        except Exception:
            print("The oracle squints. That was not a number.")
            raise SystemExit(0)
        if guess != ans:
            print("The timeline rejects your prophecy. Try again in another universe.")
            raise SystemExit(0)
        break
    elif choice == "3":
        print("You turn away before the future notices you.")
        raise SystemExit(0)
    else:
        print("The oracle does not understand that ritual.")
        raise SystemExit(0)

print("The future nods. You were... inevitable.")
print(FLAG)