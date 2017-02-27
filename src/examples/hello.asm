section .data
    msg db      "hello, world!\n"

section .text
    global _start
_start:
    mov     rdi, 1
    mov     bx, 10000
    mov     ax, 10000
    add     bx, ax 
    add     bx, 10000
    add     bx, 10000 
    add     bx, 10000 
    add     bx, 10000 
    add     bx, 10000 
    add     bx, 10000 
    mov     rax, 1
    mov     rsi, msg
    mov     rdx, 13
    syscall
    mov    rax, 60
    mov    rdi, 0
    syscall
