import os
import secrets
import string
from itertools import cycle

flag = os.getenv("FLAG", "Alpaca{FAKEFAKEFAKEFAKE}").encode()
assert flag.startswith(b"Alpaca{")

# key = b"???????", e,g, abcdefg
key = b"".join(secrets.choice(string.ascii_letters).encode() for _ in range(7))
assert len(key) == 7

c = bytes([c1 ^ c2 for c1, c2 in zip(flag, cycle(key))])
print(c.hex())
