import random
from pwn import *

HOST = "localhost"
PORT = 1337

MASK32 = 0xFFFFFFFF
N = 128

# Ref: https://zenn.dev/hk_ilohas/articles/mersenne-twister-previous-state
def un_bitshift_right_xor(x, shift):
    y = x
    i = 1
    while i * shift < 32:
        y = x ^ (y >> shift)
        i += 1
    return y & MASK32

def un_bitshift_left_xor(x, shift, mask):
    y = x
    i = 1
    while i * shift < 32:
        y = x ^ ((y << shift) & mask)
        i += 1
    return y & MASK32

def untemper(x):
    x = un_bitshift_right_xor(x, 18)
    x = un_bitshift_left_xor(x, 15, 0xEFC60000)
    x = un_bitshift_left_xor(x, 7, 0x9D2C5680)
    x = un_bitshift_right_xor(x, 11)
    return x & MASK32

def get_prev_state(state):
    for i in range(623, -1, -1):
        result = 0
        tmp = state[i]
        tmp ^= state[(i + 397) % 624]
        if (tmp & 0x80000000) == 0x80000000:
            tmp ^= 0x9908B0DF
        result = (tmp << 1) & 0x80000000

        tmp = state[(i - 1 + 624) % 624]
        tmp ^= state[(i + 396) % 624]
        if (tmp & 0x80000000) == 0x80000000:
            tmp ^= 0x9908B0DF
            result |= 1
        result |= (tmp << 1) & 0x7FFFFFFF
        state[i] = result & MASK32
    return state


io = remote(HOST, PORT)

for _ in range(624 - N):
    io.sendlineafter(b"> ", b"1")
    io.recvline()

outputs = []
for _ in range(624):
    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"]")
    outputs.append(int(io.recvline().strip()))

mt_state = [untemper(x) for x in outputs]
prev_state = get_prev_state(mt_state[:])

io.sendlineafter(b"> ", b"2")
io.recvuntil(b"i = ")
i = int(io.recvline().strip())

rng_future = random.Random()
rng_future.setstate((3, tuple(mt_state + [624]), None))
future_guess = 0

for _ in range(i):
    future_guess = rng_future.getrandbits(32)
future_guess = rng_future.getrandbits(32)
io.sendlineafter(b"Speak the next omen > ", str(future_guess).encode())

io.recvuntil(b"i = ")
i_line = io.recvline().strip().rstrip(b"?")
i = int(i_line)

rng_past = random.Random()
rng_past.setstate((3, tuple(prev_state + [0]), None))
past_guess = 0

for _ in range(i):
    past_guess = rng_past.getrandbits(32)
past_guess = rng_past.getrandbits(32)
io.sendlineafter(b"Recall the past > ", str(past_guess).encode())
io.interactive()

