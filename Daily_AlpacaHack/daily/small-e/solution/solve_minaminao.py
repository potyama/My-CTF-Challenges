from Crypto.Util.number import long_to_bytes

with open("../distfiles/output.txt") as f:
    n = int(f.readline().removeprefix("n = ").strip())
    e = int(f.readline().removeprefix("e = ").strip())
    c = int(f.readline().removeprefix("c = ").strip())

low = 0
high = n
while low < high:
    mid = (low + high) // 2
    if pow(mid, e, n) < c:
        low = mid + 1
    else:
        high = mid

print(long_to_bytes(low).decode())
