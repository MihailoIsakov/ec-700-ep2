section .data
    msg db      "hello, world!\n"

section .text
    global _start
_start:
    mov     rdi, 1
    mov     bx, 20000
    mov     ax, 20000
    add     bx, ax 
    mov     cx, bx 
    mov     r8, rcx 
    mov     rdx, rbx 
    push    rdx
    push    rbx
    mov     bx, 0
    mov     r8, 100 
    mov     rax, qword [rsp]
    mov     rax, 1
    mov     r12, qword [rsp+8]
    pop     r10
    mov     rsi, msg
    mov     rdx, 13
    syscall
    mov    rax, 60
    mov    rdi, 0
    syscall
