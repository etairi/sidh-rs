;*******************************************************************************************
; SIDH: an efficient supersingular isogeny cryptography library
;
; Abstract: utility functions in x64 assembly for P751 on Windows
;*******************************************************************************************

  .const
; Under Windows we need to use RCX and RDX as registers for the first two parameters as that is 
; the usual calling convention (cf. https://docs.microsoft.com/en-us/cpp/build/parameter-passing).
reg_p1 equ rcx
reg_p2 equ rdx

; Digits of 3^238 - 1
three238m1_0 equ 0EDCD718A828384F8h
three238m1_1 equ 0733B35BFD4427A14h
three238m1_2 equ 0F88229CF94D7CF38h
three238m1_3 equ 063C56C990C7C2AD6h
three238m1_4 equ 0B858A87E8F4222C7h
three238m1_5 equ 0254C9C6B525EAF5h

  .code
;***********************************************************************
;  Check less than 3^238
;  Operation: 
;  Set result [reg_p2] to 0 if the input [reg_p1] scalar is <= 3^238.
;*********************************************************************** 
checklt238_asm proc
  push   r12
  push   r13

  ; Zero rax for later use.
  xor    rax, rax

  ; Set [R10,...,R15] = 3^238
  mov    r10, three238m1_0
  mov    r11, three238m1_1
  mov    r12, three238m1_2
  mov    r13, three238m1_3
  mov    r14, three238m1_4
  mov    r15, three238m1_5

  ; Set [R10,...,R15] = 3^238 - scalar
  sub    r10, [reg_p1]
  sbb    r11, [reg_p1+8]
  sbb    r12, [reg_p1+16]
  sbb    r13, [reg_p1+24]
  sbb    r14, [reg_p1+32]
  sbb    r15, [reg_p1+40]

  ; Save borrow flag indicating 3^238 - scalar < 0 as a mask in AX
  sbb    rax, 0
  mov    [reg_p2], rax

  pop    r13
  pop    r12
  ret
checklt238_asm endp

;***********************************************************************
;  Multiply by 3.
;  Operation: 
;  Set scalar [reg_p1] = 3*scalar [reg_p1].
;*********************************************************************** 
mulby3_asm proc
  push   r12
  push   r13

  ; Set [R10,...,R15] = scalar
  mov    r10, [reg_p1]
  mov    r11, [reg_p1+8]
  mov    r12, [reg_p1+16]
  mov    r13, [reg_p1+24]
  mov    r14, [reg_p1+32]
  mov    r15, [reg_p1+40]

  ; Add scalar twice to compute 3*scalar
  add    [reg_p1], r10
  adc    [reg_p1+8], r11
  adc    [reg_p1+16], r12
  adc    [reg_p1+24], r13
  adc    [reg_p1+32], r14
  adc    [reg_p1+40], r15
  add    [reg_p1], r10
  adc    [reg_p1+8], r11
  adc    [reg_p1+16], r12
  adc    [reg_p1+24], r13
  adc    [reg_p1+32], r14
  adc    [reg_p1+40], r15

  pop    r13
  pop    r12
  ret
mulby3_asm endp
  end
