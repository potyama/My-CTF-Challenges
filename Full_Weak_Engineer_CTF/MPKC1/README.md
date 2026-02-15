# MPKC1

|ジャンル|問題名|作問者|タグ|最終スコア|Solve数|
|---|---|---|---|---|---|
|Crypto|MPKC1|chama|Medium|236|91|
## Description(問題文)

Simultaneous equations are fascinating:)

`tar -zxvf mpkc1.tar.gz`

## Solution

I’ll apologize in advance. MPKC1 and 2 are due to my lack of skill :cry:
Originally, I planned to make challenges themed around multivariate public-key cryptography (MPKC).

Since I was thinking of releasing a paper-based implementation in MPKC2, I made this as an introduction.

The overall flow is:

1. Create a secret bitstring `t_secret`
2. Generate the secret parameter `Z` with the  `z_vector_from_t` function
3. Convert each plaintext line `s` in plain.txt into ciphertexts using `make_sample` function and collect them
4. Convert the flag in the same way as in step 3

You can view this as a simple linear cipher, and since the plaintext list is public, a known-plaintext attack works.

$$
C = P \oplus (LZ)
$$

So,

$$
P \oplus C = LZ
$$

The only unknown is $Z$.
You can recover it by solving with Gaussian elimination.

```python
from pathlib import Path
from Crypto.Util.number import bytes_to_long, long_to_bytes

PATH = "public.txt"

tok = [
    ln.strip()
    for ln in Path(PATH).read_text(encoding="utf-8").splitlines()
    if ln.strip() and not ln.lstrip().startswith("#")
]

D = None
samples = []
flag = None

i = 0
while i < len(tok):
    ln = tok[i]

    if ln.startswith("D="):
        D = int(ln.split("=", 1)[1])
        i += 1
        continue

    if ln == "BEGIN SAMPLE":
        m = int(tok[i + 1].split("=", 1)[1])
        if tok[i + 2] != "L:":
            raise ValueError("Bad SAMPLE: missing L:")
        L = tok[i + 3 : i + 3 + m]
        P = tok[i + 3 + m].split("=", 1)[1].strip()
        C = tok[i + 4 + m].split("=", 1)[1].strip()
        if tok[i + 5 + m] != "END SAMPLE":
            raise ValueError("Bad SAMPLE: missing END SAMPLE")
        samples.append((m, L, P, C))
        i += 6 + m
        continue

    if ln == "BEGIN FLAG":
        m = int(tok[i + 1].split("=", 1)[1])
        if tok[i + 2] != "L:":
            raise ValueError("Bad FLAG: missing L:")
        L = tok[i + 3 : i + 3 + m]
        C = tok[i + 3 + m].split("=", 1)[1].strip()
        if tok[i + 4 + m] != "END FLAG":
            raise ValueError("Bad FLAG: missing END FLAG")
        flag = (m, L, C)
        i += 5 + m
        continue

    i += 1

if D is None or flag is None:
    raise ValueError("D and/or FLAG not found")

b2l = bytes_to_long if bytes_to_long else (lambda b: int.from_bytes(b, "big"))
coeff_mask = (1 << D) - 1
rows = []

for m, L, P, C in samples:
    pb = bytes.fromhex(P)
    cb = bytes.fromhex(C)
    p = (b2l(pb) >> (len(pb) * 8 - m)) if m else 0
    c = (b2l(cb) >> (len(cb) * 8 - m)) if m else 0
    y = p ^ c

    for idx, h in enumerate(L):
        hb = bytes.fromhex(h)
        row = (b2l(hb) >> (len(hb) * 8 - D)) & coeff_mask
        rhs = (y >> (m - 1 - idx)) & 1
        rows.append(row | (rhs << D))

r = 0
piv = []
M = len(rows)

for col in range(D):
    bit = 1 << (D - 1 - col)
    pivot = next((k for k in range(r, M) if rows[k] & bit), None)
    if pivot is None:
        continue
    rows[r], rows[pivot] = rows[pivot], rows[r]
    piv.append(bit)

    pr = rows[r]
    for k in range(M):
        if k != r and (rows[k] & bit):
            rows[k] ^= pr

    r += 1
    if r == M:
        break

for k in range(r, M):
    if (rows[k] & coeff_mask) == 0 and ((rows[k] >> D) & 1):
        raise ValueError("Inconsistent system")

z = 0
for j in range(r - 1, -1, -1):
    bit = piv[j]
    rhs = (rows[j] >> D) & 1
    rhs ^= ((((rows[j] & coeff_mask) & ~bit) & z).bit_count() & 1)
    z = (z & ~bit) | (rhs * bit)

mf, Lf, Cf = flag
cb = bytes.fromhex(Cf)
c = (b2l(cb) >> (len(cb) * 8 - mf)) if mf else 0

y_flag = 0
for idx, h in enumerate(Lf):
    hb = bytes.fromhex(h)
    row = (b2l(hb) >> (len(hb) * 8 - D)) & coeff_mask
    if ((row & z).bit_count() & 1):
        y_flag |= 1 << (mf - 1 - idx)

p = c ^ y_flag
pad = (-mf) % 8
num = p << pad
nbytes = (mf + pad) // 8

out = long_to_bytes(num, nbytes)
print(out.decode())
```

## Flag

`fwectf{1_w0k3_up_w1th_th3_1d34!_A3xbkTObddZ7SNLVgLBgy9uW52l0SOnrK8H}`

