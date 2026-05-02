from sage.all import var
import cuso
from Crypto.Util.number import long_to_bytes


def load_params(path="output.txt"):
    data = {}
    for line in open(path, "r", encoding="utf-8"):
        line = line.strip()
        if not line or " = " not in line:
            continue
        k, v = line.split(" = ", 1)
        data[k.strip()] = int(v.strip())
    return data


params = load_params()
N = params["N"]
e = params["e"]
c = params["c"]
pbar = params["pbar"]
kbits = params["kbits"]

x = var("x")
f = x + pbar
roots = cuso.find_small_roots(
    [f],
    bounds={x: (0, 2 ** kbits)},
    modulus="p",
    modulus_multiple=N,
    modulus_lower_bound=2 ** ((N.bit_length() // 2) - 1),
)

if not roots:
    print("no roots found")
else:
    p = pbar + int(roots[0][x])
    if N % p != 0:
        print("root found but not a factor")
    else:
        q = N // p
        d = pow(e, -1, (p - 1) * (q - 1))
        m = pow(c, d, N)
        print(long_to_bytes(m).decode())