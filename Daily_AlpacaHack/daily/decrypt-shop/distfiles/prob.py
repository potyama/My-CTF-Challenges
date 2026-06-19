from Crypto.Util.number import bytes_to_long, getPrime, inverse
import os


flag = os.environ.get("FLAG", "Alpaca{REDACTED}").encode()

p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = inverse(e, phi)

c = pow(bytes_to_long(flag), e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print("Give me a ciphertext. I will decrypt it, unless it is the flag ciphertext.")

while True:
    try:
        x = int(input("> "))
    except:
        print("invalid")
        exit(0)

    if not 0 <= x < n:
        print("out of range")
        exit(0)

    if x == c:
        print("no")
        exit(0)

    m = pow(x, d, n)
    print(m)
