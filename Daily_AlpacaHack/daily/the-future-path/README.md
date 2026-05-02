# The future path
> 未来へGO!🚀


```py
import os
import random
import secrets

FLAG = os.getenv("FLAG")
rng = random.Random(secrets.randbits(64))


print("=== The Future? ===")
print("A small oracle hums... it only speaks in 32-bit prophecies.")
print("Menu: [1] consult the present  [2] name the future  [3] leave quietly")

pos = 0
while True:
    choice = input("> ").strip()
    if choice == "1":
        print(f"[present #{pos:03d}] {rng.getrandbits(32)}")
        pos += 1
    elif choice == "2":
        i = secrets.randbelow(128)
        for _ in range(i):
            rng.getrandbits(32)
        ans = rng.getrandbits(32)
        print(f"The oracle points to the timeline: i = {i}")
        try:
            guess = int(input("Speak the next omen > ").strip(), 0)
        except Exception:
            print("The oracle squints. That was not a number.")
            raise SystemExit(0)
        if guess != ans:
            print("The timeline rejects your prophecy. Try again in another universe.")
            raise SystemExit(0)
        break
    elif choice == "3":
        print("You turn away before the future notices you.")
        raise SystemExit(0)
    else:
        print("The oracle does not understand that ritual.")
        raise SystemExit(0)

print("The future nods. You were... inevitable.")
print(FLAG)
```
Mediumにしては難しかったかもしれませんが、Cryptoではツールを用いることもあります。
今回、内容が難しかった方も、ぜひもう一度挑戦してみていただけると嬉しいです。

ただ、問題の本質とは関係のない面倒さも含まれてしまっていたので、その点は反省しています。申し訳ありませんでした。

# 解法

今回の問題で使われているPythonの `Random.random` は、暗号論的に安全ではありません。

一般に、`Random.random`で用いられている Mersenne Twister という疑似乱数生成器は、32bitの出力を624個集めることで内部状態を復元できてしまうことが知られています。
今回の問題では 1 を何度でも集められるため、624個集めるのは容易です。

あとは内部状態を復元するだけですが、これを自前で実装するのは大変です。こういうときはツールを使いましょう。
ChatGPT などのLLMに聞いてもよいですし、`python random.random crack`などで調べれば使えるツールが見つかります。

例えば、以下のようなものがあります。
https://pypi.org/project/randcrack/

あとはこれを用いて、問題コードに合うように solver を書けば、フラグを得ることができます。

なお、WSL などの環境では、pip installをそのまま使うとエラーになってインストールできないことがあるかもしれません。
その場合は、Python仮想環境を使うのがおすすめです。例えば、venv、uv、condaなどがあります。

私は普段、SageMathを入れるときにcondaを使っているので、今回もcondaを使いました。
ただ、uvやvenvでも問題ありません。
```py
# https://pypi.org/project/randcrack/
from randcrack import RandCrack
from pwn import *


HOST = "localhost"
PORT = 1337

io = remote(HOST, PORT)

rc = RandCrack()
for _ in range(624):
    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"]")
    val = io.recvline()
    rc.submit(int(val.decode()))

io.sendlineafter(b"> ", b"2")
io.recvuntil(b"i = ")
i = int(io.recvline().strip())
guess = [rc.predict_getrandbits(32) for _ in range(128)][i]
io.sendlineafter(b"> ", str(guess).encode())
io.interactive()

```
