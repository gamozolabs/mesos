[bits 64]

section .code

global mainCRTStartup
mainCRTStartup:
    ; This should be at program.exe+0x1000
    nop

    ; This should be at program.exe+0x1001
    jmp mainCRTStartup

