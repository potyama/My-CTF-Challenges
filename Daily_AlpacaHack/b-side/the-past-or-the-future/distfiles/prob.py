import os
import random
import secrets

FLAG = os.getenv("FLAG")
N = 128

rng = random.Random(secrets.randbits(64))

past = [rng.getrandbits(32) for _ in range(N)]

print("=== The Past or the Future? ===")
print("An oracle whispers... it only speaks in 32-bit omens.")
print("Menu: [1] consult the present  [2] name the future  [3] leave quietly")

pos = 0
while True:
    choice = input("> ").strip()
    if choice == "1":
        val = rng.getrandbits(32)
        print(f"[present] {val}")
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

        i = secrets.randbelow(N)
        print("The oracle turns its gaze backward.")
        print(f"The oracle asks: what was the omen at index i = {i}?")
        try:
            guess = int(input("Recall the past > ").strip(), 0)
        except Exception:
            print("The oracle frowns. That was not a number.")
            raise SystemExit(0)
        if guess != past[i]:
            print("Your memory fades. The past slips away.")
            raise SystemExit(0)
        break
    elif choice == "3":
        print("You turn away before the future notices you.")
        raise SystemExit(0)
    else:
        print("The oracle does not understand that ritual.")

print("The oracle smiles. You remembered the unrememberable.")
print(FLAG)
