from core_lib import setup_secret_general


def decrypt_from_hex_packed(hex_str, S):
    K = S.K
    m = K.m
    q = 1 << m
    mask = (1 << m) - 1

    def affine_prepare(Mb):
        M, b = Mb
        n = len(M)

        A = [row[:] + [0] * n for row in M]
        for i in range(n):
            A[i][n + i] = 1

        r = 0
        for c in range(n):
            piv = next((i for i in range(r, n) if A[i][c] != 0), None)
            if piv is None:
                continue
            A[r], A[piv] = A[piv], A[r]

            if A[r][c] != 1:
                invp = K.inv(A[r][c])
                A[r] = [K.mul(x, invp) for x in A[r]]

            for i in range(n):
                if i == r:
                    continue
                f = A[i][c]
                if f:
                    A[i] = [K.add(A[i][j], K.mul(f, A[r][j])) for j in range(2 * n)]
            r += 1

        if r < n:
            raise ValueError("singular matrix over K")

        Minv = [row[n:] for row in A]

        Minv_b = []
        for i in range(n):
            s = 0
            row = Minv[i]
            for j, aij in enumerate(row):
                if aij:
                    s = K.add(s, K.mul(aij, b[j]))
            Minv_b.append(s)

        return Minv, Minv_b

    def affine_apply(pre, y):
        Minv, Minv_b = pre
        n = len(Minv)
        out = []
        for i in range(n):
            s = Minv_b[i]
            row = Minv[i]
            for j, aij in enumerate(row):
                if aij:
                    s = K.add(s, K.mul(aij, y[j]))
            out.append(s)
        return out

    def ext_pow(vec, e, mod):
        n = len(vec)
        mod = mod[:n]

        def mul(a, b):
            tmp = [0] * (2 * n - 1)
            for i, ai in enumerate(a):
                if ai == 0:
                    continue
                for j, bj in enumerate(b):
                    if bj:
                        tmp[i + j] = K.add(tmp[i + j], K.mul(ai, bj))

            for d in range(2 * n - 2, n - 1, -1):
                coef = tmp[d]
                if coef:
                    base = d - n
                    for j, aj in enumerate(mod):
                        if aj:
                            tmp[base + j] = K.add(tmp[base + j], K.mul(coef, aj))
                    tmp[d] = 0
            return tmp[:n]

        res = [0] * n
        res[0] = 1
        base = vec[:]
        while e:
            if e & 1:
                res = mul(res, base)
            base = mul(base, base)
            e >>= 1
        return res

    data = bytes.fromhex(hex_str)
    if len(data) < 8:
        raise ValueError("hex too short (missing header)")

    elem_count = int.from_bytes(data[:4], "big")
    pad_bits = int.from_bytes(data[4:8], "big")
    payload = data[8:]

    Lbits = elem_count * m
    Lbytes = (Lbits + 7) // 8
    if len(payload) != Lbytes:
        if len(payload) < Lbytes:
            payload = b"\x00" * (Lbytes - len(payload)) + payload
        else:
            raise ValueError("payload length mismatch")

    payload_int = int.from_bytes(payload, "big")
    ct = [(payload_int >> (Lbits - m * (i + 1))) & mask for i in range(elem_count)]

    if len(ct) % S.n:
        raise ValueError("ciphertext length not divisible by n")

    hs = [pow(ei, -1, (q ** ni) - 1) for ni, ei in zip(S.partition, S.e_list)]
    t_pre = affine_prepare(S.t_forward)
    s_pre = affine_prepare(S.s_forward)

    rec = []
    for off in range(0, len(ct), S.n):
        eta = ct[off : off + S.n]
        v = affine_apply(t_pre, eta)

        u = []
        pos = 0
        for ni, h, block in zip(S.partition, hs, S.blocks):
            chunk = v[pos : pos + ni]
            pos += ni
            u.extend(ext_pow(chunk, h, block.modulus))

        rec.extend(affine_apply(s_pre, u))

    out_int = 0
    for a in rec:
        out_int = (out_int << m) | (a & mask)

    total_bits = len(rec) * m
    if pad_bits:
        out_int >>= pad_bits
        total_bits -= pad_bits

    out_len = (total_bits + 7) // 8
    return out_int.to_bytes(out_len, "big") if out_len else b""


SEED = 20250829
M = 8
PARTITION = [7]
BLIST = [3]
MODULI = [[1, 1, 0, 0, 0, 0, 0, 1]]

CT_HEX = (
    "000000460000000863306b8beb63d7f7f73160467fca983fcf637c20905e1d7ca653f4a5137d672b"
    "b8c40da87994b9cc99ff5981900ae419c270973db9b078ee1a17f5bf79da2dd5aab9bbc6d38b"
)

S = setup_secret_general(SEED, M, PARTITION, MODULI, b_list=BLIST)
pt = decrypt_from_hex_packed(CT_HEX, S)
print(pt.decode())


