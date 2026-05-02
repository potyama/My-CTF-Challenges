from Crypto.Util.number import long_to_bytes


def load_params(path="output.txt"):
    data = {}
    for line in open(path, "r", encoding="utf-8"):
        line = line.strip()
        if not line or " = " not in line:
            continue
        k, v = line.split(" = ", 1)
        data[k.strip()] = Integer(v.strip())
    return data


params = load_params()
N = params["N"]
e = params["e"]
c = params["c"]
pbar = params["pbar"]
kbits = params["kbits"]

PR.<x> = PolynomialRing(Zmod(N))
f = x + pbar
roots = f.small_roots(X=2 ** kbits, beta=0.3)

if not roots:
    print("no roots found")
else:
    p = pbar + Integer(roots[0])
    if N % p != 0:
        print("root found but not a factor")
    else:
        q = N // p
        d = inverse_mod(e, (p - 1) * (q - 1))
        m = power_mod(c, d, N)
        print(long_to_bytes(int(m)).decode())