from Crypto.Util.number import long_to_bytes
from sage.all import *

p = Integer(0xc9f519a737db44dfe207c70d8bb8cc736ca33fef9da3b164e990ee56d7d70d3064c3d8fa3feac27a9101b147ae21b42583f80c711476b913aae4aeabcfd31e2b)
a = Integer(0x2b3802246fa86fd6ceb2e68aff54f862eda9e591721d250ea0cb9abc1977396474711e6819affe97aa55d13d9f551b4d2a9201e1e0500779cf29df19ab7aaaee) % p
b = Integer(0x872c6ede0741321f1cb3836dabd68cbdeb257f92cd98091a1a3c311884b6317af364892cc5a8d77b801bf25e2eeda46c5218e5ab888f03b427cc8f0f93047a98) % p

Px = Integer(130737096243592821581892868792449130410991364212554023515870971507682317978011674831210370823035884008564272801710897774023235436093293609121626749719878) % p
Py = Integer(9934258647013010474664215798645012456088189517053868504851072694235288612134502872240155321081774267254574240673083688568562135562420947379720253756545954) % p
Qx = Integer(698778526282560729782421452951864139075482475519112988619038996601263553466262563766962012040372466625187643082851279701308165461041455155605521785059579) % p
Qy = Integer(9801151623484835074141999292657329060135603960214342784573759533658439085479849537733569628649771325524543526896351004756733398451521494470556428527069332) % p

F = GF(p)
E = EllipticCurve(F, [a, b])
P = E(Px, Py)
Q = E(Qx, Qy)

n = E.cardinality()
if n != p:
    raise ValueError(f"Not anomalous: #E(Fp)={n} != p. Smart attack not applicable as-is.")

def lift_point_to_Qp(EQp, PF, p, prec):
    K = EQp.base_ring()
    x0 = ZZ(PF[0])
    y0 = ZZ(PF[1])
    xK = K(x0)

    rhs = xK**3 + EQp.a4()*xK + EQp.a6()

    ys = rhs.sqrt(all=True)
    if not ys:
        raise ValueError("Qp sqrt failed; increase precision.")

    target = Integer(y0 % p)
    for yK in ys:
        if Integer(yK.lift() % p) == target:
            return EQp(xK, yK)

    return EQp(xK, -ys[0])

def smart_k(E, P, Q, p, start_prec=80, max_prec=220, step=40):
    a = Integer(E.a4()) % p
    b = Integer(E.a6()) % p

    for prec in range(start_prec, max_prec + 1, step):
        try:
            K = Qp(p, prec)
            EQp = EllipticCurve(K, [K(a), K(b)])

            Pp = lift_point_to_Qp(EQp, P, p, prec)
            Qp_ = lift_point_to_Qp(EQp, Q, p, prec)

            P1 = p * Pp
            Q1 = p * Qp_

            tP = -P1[0] / P1[1]
            tQ = -Q1[0] / Q1[1]

            u = tQ / tP
            k = Integer(u.lift() % p)

            if k * P == Q:
                return k
        except Exception:
            pass

    raise ValueError("Smart attack failed; precision/assumption issue.")

k = smart_k(E, P, Q, p)

print("k =", k)
m = long_to_bytes(int(k))