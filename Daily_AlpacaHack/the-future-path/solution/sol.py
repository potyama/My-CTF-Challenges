# https://github.com/tna0y/Python-random-module-cracker
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
