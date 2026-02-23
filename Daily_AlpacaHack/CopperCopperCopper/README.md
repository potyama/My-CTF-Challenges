# CopperCopperCopper
> 見て！アルパカがいるよ！ C(・´(ェ)｀・)u

```python
import os
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = os.environ.get("FLAG", "Alpaca{ffffakeflagggg}")

KBITS = 200  # unknown lower bits of p

p = getPrime(512)
q = getPrime(512)
N = p * q
e = 65537

m = bytes_to_long(FLAG.encode())
c = pow(m, e, N)

pbar = p & (~((1 << KBITS) - 1))

print("N =", N)
print("e =", e)
print("c =", c)
print("pbar =", pbar)
print("kbits =", KBITS)

```

# What You Learn From This Challenge
- Understand that knowing the most significant bits of $`p`$ (i.e., the least significant bits are unknown) can directly lead to factoring an RSA modulus.
- Learn how to use SageMath’s `small_roots` to apply Coppersmith’s Attack.


# Solution
## Overview
From the challenge code, you are given `pbar = p & (~((1 << KBITS) - 1))`, which is the prime $`p`$ with its lower $`kbits = 200`$ bits rounded down to zero.

Write the prime $`p`$ as

$$
p = 2^k \cdot t + r,\quad 0 \le r < 2^k
$$

where $`t`$ is the quotient $`t = \left\lfloor \dfrac{p}{2^k} \right\rfloor`$ and $`r`$ is the remainder $`r = p \bmod 2^k`$.

Then we have

$$
p_{\mathrm{bar}} = 2^k \cdot t
$$

so we can express

$$
p = p_{\mathrm{bar}} + x\quad 0 \le x < 2^k.
$$

## The Idea Behind Coppersmith’s Attack
:::note info
This section explains the theory with references to papers, so if you’re a beginner or you find lattice-based crypto intimidating, it’s fine to read only the last two sentences.
:::

Let’s go slightly deeper. In the simplest (univariate) setting, consider the following problem [1]:

- You are given an integer $`N`$ and a polynomial $`f(x)\in\mathbb{Z}[x]`$.
  - (For convenience, let $`\delta=\deg f`$.)
  - Here, $`\deg f`$ (degree) means the largest exponent appearing in $`f(x)`$.
- You want to find an integer $`x_0`$ such that:

$$
f(x_0)\equiv 0 \pmod N,\qquad |x_0|<X.
$$

A representative theorem by Coppersmith states that if $`f`$ is monic (its leading coefficient is 1), then when $`|x_0|`$ is sufficiently small, you can recover $`x_0`$ in polynomial time.

In RSA-style attacks, the modulus of the congruence is often not $`N`$ itself but an unknown large divisor of $`N`$ [2].  
So in practice, we consider:

- Let $`b\mid N`$ be unknown but sufficiently large, and suppose we know a lower bound $`b\ge N^{\beta}`$ [^foo].
- We want to find a small $`x_0`$ such that:

$$
f(x_0)\equiv 0 \pmod b,\qquad |x_0|<X.
$$

Coppersmith’s theorem still applies in this setting, and using the assumption that the unknown divisor satisfies $`b\ge N^\beta`$, we can estimate the range of recoverable small roots [2].  
Roughly speaking, if $`f`$ is monic of degree $`\delta`$, then for any constant $`\varepsilon>0`$,

$$
|x_0|\le N^{\left(\tfrac{\beta^2}{\delta}\right)-\varepsilon}
$$

is within the recoverable range.

In our case, since $`p\approx N^{1/2}`$, we have $`\beta\approx 1/2`$. If $`f`$ is linear, then $`\delta=1`$, and thus:

$$
|x_0|\le N^{\left(\tfrac{\left(\frac{1}{2}\right)^2}{1}\right)-\varepsilon}=N^{\frac{1}{4}-\varepsilon}.
$$

Therefore,
**in this challenge, if we know about $`1/4`$ of the bits of $`N`$ (equivalently about half the bits of $`p`$) as the most significant bits of $`p`$, we can recover the small root of $`f(x)\equiv 0\pmod b`$, which reveals $`f(x)`$—namely, $`p`$.**

## Attack Outline
Since both $`p`$ and $`q`$ are 512-bit primes, we can treat

$$
p \approx q \approx \sqrt{N} \approx N^{1/2}.
$$

Here $`\mathrm{bitlen}(N)\approx 1024`$, so

$$
N^{1/4} \approx 2^{1024/4} = 2^{256}.
$$

On the other hand,

$$
|x| < 2^{200} < 2^{256} \approx N^{1/4},
$$

so the instance is solvable via Coppersmith’s Attack.

Now define

$$
f(x) = p_{\mathrm{bar}} + x.
$$

For the true solution $`x=x_0`$,

$$
f(x_0)=p_{\mathrm{bar}}+x_0=p,
$$

so

$$
f(x_0) \equiv 0 \pmod p.
$$

Since $`p\mid N`$, this matches the "small root modulo an unknown factor of $`N`$" pattern, and Coppersmith’s Attack can recover $`x_0`$ with $`|x_0|<2^{200}`$.

Then we complete the factorization by

$$
q = \frac{N}{p}.
$$

## Solver Code
If you want to write a solver using SageMath, you can use the following code.
```python
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
```
To run it, save it as a Sage script such as `sol.sage`, then execute:
```terminal
sage sol.sage
```
Note that a plain Sage installation may not include PyCryptodome. If you haven’t installed it yet, run the following command [3].
```terminal
sage -pip install pycryptodome
```

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes


def load_params(path="output.txt"):
    data = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
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

PR = PolynomialRing(Zmod(N), names=("x"))
(x) = PR.gen()

f = x + pbar
roots = f.small_roots(X=2 ** int(kbits), beta=0.3)

if not roots:
    print("no roots found")
    exit(1)

p = Integer(pbar) + Integer(roots[0])
if N % p != 0:
    print("root found but not a factor")
    exit(1)

q = N // p
d = inverse_mod(e, (p - 1) * (q - 1))
m = power_mod(c, d, N)

flag = long_to_bytes(int(m))
print(flag.decode())
```
You can also import Sage libraries from Python code. In that case, use the second script below. Save it as `sol.py` and run:
```terminal
sage -python sol.py
```
Finally, there are implementations of Coppersmith-style small-root finding beyond Sage’s built-in `small_roots`. For example, the following repository provides Coppersmith techniques for multivariate polynomials:

https://github.com/keeganryan/cuso

If you use that library, you can write a solver like the third script below. 
```python
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
```

# Conclusion
Running any of these solvers will recover the flag.

If you notice that the challenge is "MSB leakage of $p$ + Coppersmith’s Attack," then the solver is relatively straightforward, because many public references already demonstrate the exact small_roots approach.
For instance, inaz2’s article explains how to reconstruct $p$ with a concrete Sage script [4].

That said, lattice-based crypto (including Coppersmith) can feel hard at first, because fully understanding why it works touches many topics—number theory, polynomial rings, lattices, LLL, and more.
Rather than trying to finish every proof and derivation end-to-end immediately, it often helps to break questions down: "What theorem justifies this step?", "What does this parameter mean?" Then you can ask an AI tool or talk it through with friends, one piece at a time.
When I design challenges, I try to keep the "one challenge, one technique" philosophy so you walk away with something concrete. Even if a problem feels difficult, I hope you’ll give it a shot!

## Bonus

- There are three occurrences of "copper."

Writing copper in leetspeak gives "C0pp3r," so it’s repeated three times.

- The alpaca in the statement:

It’s "C(・´(ェ)｀・)u", where the hands form "C" and "u", i.e., "Cu" (copper).

### References
[1] https://link.springer.com/chapter/10.1007/3-540-68339-9_14

[2] https://link.springer.com/chapter/10.1007/3-540-68339-9_16

[3] https://github.com/alpacahack/resources/blob/main/resources/SageMath.md#sagemath-%E3%81%A7%E3%81%AE-pip-install

[4] https://inaz2.hatenablog.com/entry/2016/01/20/022936