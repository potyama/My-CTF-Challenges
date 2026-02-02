E = EllipticCurve(QQbar, [5,10])
P = E(1,4)
Q = E(3/2, sqrt(334)/4)
x, y = (P-Q).xy()
print(f"CSL24{{{x}:{y}}}".replace("?", ""))
# CSL24{291.2053350599766:4969.490696019601}