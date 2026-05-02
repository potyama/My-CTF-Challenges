# Find XOR key
> paca?

```python
import os
import secrets
import string
from itertools import cycle

flag = os.getenv("FLAG", "Alpaca{FAKEFAKEFAKEFAKE}").encode()
assert flag.startswith(b"Alpaca{")

# key = b"???????", e,g, abcdefg
key = b"".join(secrets.choice(string.ascii_letters).encode() for _ in range(7))
assert len(key) == 7

c = bytes([c1 ^ c2 for c1, c2 in zip(flag, cycle(key))])
print(c.hex())
```

## 解法

今回の問題では、keyを以下コードで生成しています。

```python
key = b"".join(secrets.choice(string.ascii_letters).encode() for _ in range(7))
```
また、assert文からkeyは7バイトであること、keyを繰り返してXORしていることがわかります。

ここで、XORには以下の性質があることを思い出しましょう。

```text
A ^ B = C
C ^ B = A
```

つまり、以下の式も成立します。

```text
暗号文 ^ 鍵 = 平文
暗号文 ^ 平文 = 鍵
```

もう少し、この内容について追ってみましょう。
問題コードから、今回の暗号化は次の式で表せます。

```text
flag[i] ^ key[i] = c[i] 
```
つまり、
```text
flag[0] ^ key[0] = c[0]  
flag[1] ^ key[1] = c[1]  
...
flag[i-1] ^ key[i-1] = c[i-1]
flag[i] ^ key[i] = c[i]
```
となります。
ここでフラグの先頭文字は`Alpaca{`であるため、

```text
c[0] ^ ord('A') = key[0] 
c[1] ^ ord('l') = key[1]  
...
c[6] ^ ord('{') = key[6] 
```

となり、暗号文の先頭7バイトから鍵7バイトすべてを復元できます。


flagを求める手順は次の通りです。

1. 出力されたhex文字列をbytesに戻す
2. 先頭7バイトと`b"Alpaca{"`をXORしてkeyを求める
3. そのkeyを繰り返して暗号文全体をXORする

```python
from pwn import xor

c_hex = open("output.txt").readline().strip()
c = bytes.fromhex(c_hex)

key_guess = xor(c, b"Alpaca{")[:7]
print(key_guess)

flag = xor(c, key_guess)
print(flag.decode())
```

また、CyberChefを使って求めることもできます。
下記サイトをクリックすると、keyを求めることができます。
https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'Alpaca%7B'%7D,'Standard',false)Take_bytes(0,7,false)&input=MDMxYjEzMDcyZDI4MGEyYzE4MTYzOTJmM2IwNDFkMDcwMjBkMmYxNjE5MjMyODE3MTUzYjI0MTQxZDAwMGMzOTI1MjgxYTM3MDQxNjFiDQo&ieol=CRLF&oeol=CR

上記サイトでわかったkeyを入力すると、フラグを出力できます。
https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'BwcfNIq'%7D,'Standard',false)&input=MDMxYjEzMDcyZDI4MGEyYzE4MTYzOTJmM2IwNDFkMDcwMjBkMmYxNjE5MjMyODE3MTUzYjI0MTQxZDAwMGMzOTI1MjgxYTM3MDQxNjFiDQo&ieol=CRLF&oeol=CR