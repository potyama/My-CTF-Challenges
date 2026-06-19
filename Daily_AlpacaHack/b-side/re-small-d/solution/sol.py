from Crypto.Util.number import long_to_bytes
from sage.all import Integer, floor, sqrt, var
import cuso

with open("../distfiles/output.txt") as f:
    n = int(f.readline().removeprefix("n = "))
    e = int(f.readline().removeprefix("e = "))
    c = int(f.readline().removeprefix("c = "))

x, y = var("x y")
A = (n + 1) // 2
f = x*y + A*x + 1

relations = [f]
bounds = {
    x: (0, floor(2 * e**0.27)),
    y: (-floor(2 * sqrt(n)), 0),
}
roots = cuso.find_small_roots(
    relations,
    bounds,
    modulus=e,
    unraveled_linearization_relations=[x*y + 1],
)

if not roots:
    raise ValueError("Not found")

x0 = Integer(roots[0][x])
y0 = Integer(roots[0][y])
d = (1 + x0 * (A + y0)) // e
m = pow(int(c), int(d), int(n))
print(long_to_bytes(m).decode())
