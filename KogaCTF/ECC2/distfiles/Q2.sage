p = ???
a, b = ???

E = EllipticCurve(GF(p), [a, b])

# Base point
B = ???

def fmt_point(P):
    # Infinity point
    if P.is_zero():
        return "(0:1 :0)"
    x, y = P.xy()
    return f"({int(x)}:{int(y)}:1)"

kB = []
k = 0

# collect 0B, 1B, ..., until it repeats
while (k * B) not in kB:
    kB.append(k * B)
    k += 1

ordB = k
print(f"CSL24{{{ordB}:{','.join(fmt_point(P) for P in kB)}}}")
