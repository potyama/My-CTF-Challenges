from Crypto.Util.number import long_to_bytes, inverse
from pwn import *


HOST = "localhost"
PORT = 1337

def read_value(io, name):
    io.recvuntil(f"{name} = ".encode())
    return int(io.recvline())


io = remote(HOST, PORT)

n = read_value(io, "n")
e = read_value(io, "e")
c = read_value(io, "c")

r = 2
dummy_c = c * pow(r, e, n) % n

io.sendlineafter(b"> ", str(dummy_c).encode())
masked = int(io.recvline().decode())
m = masked * inverse(r, n) % n

print(long_to_bytes(m).decode())
