# SMART_ATTACK
> We are smart.
```python
from Crypto.Util.number import bytes_to_long

FLAG = b"CSL24{REDIRECTED}"
p = 0xc9f519a737db44dfe207c70d8bb8cc736ca33fef9da3b164e990ee56d7d70d3064c3d8fa3feac27a9101b147ae21b42583f80c711476b913aae4aeabcfd31e2b
a = 0x2b3802246fa86fd6ceb2e68aff54f862eda9e591721d250ea0cb9abc1977396474711e6819affe97aa55d13d9f551b4d2a9201e1e0500779cf29df19ab7aaaee
b = 0x872c6ede0741321f1cb3836dabd68cbdeb257f92cd98091a1a3c311884b6317af364892cc5a8d77b801bf25e2eeda46c5218e5ab888f03b427cc8f0f93047a98

E = EllipticCurve(GF(p), [a, b])
P = E.random_point()
Q = bytes_to_long(FLAG) * P

print(f"{P=}\n{Q=}")

#print(E.order() - p)???

```
## Hint1
E.order()とpの値を比較してみましょう。なにか特徴があるかも？

## Hint2
ecpyという便利なライブラリがあります。
https://github.com/elliptic-shiho/ecpy

## Hint3
https://zenn.dev/anko/articles/ctf-crypto-ellipticcurve#anomalous-%E3%81%AA%E6%9B%B2%E7%B7%9A%E3%82%92%E7%94%A8%E3%81%84%E3%81%A6%E3%81%AF%E3%81%84%E3%81%91%E3%81%AA%E3%81%84-(sssa-attack)