;*******************************************************************************************
; SIDH: an efficient supersingular isogeny cryptography library
;
; Abstract: field arithmetic in x64 assembly for P751 on Windows
;*******************************************************************************************

  .const
; Under Windows we need to use RCX, RDX and R8 as registers for the first three parameters as that 
; is the usual calling convention (cf. https://docs.microsoft.com/en-us/cpp/build/parameter-passing).
reg_p1 equ rcx
reg_p2 equ rdx
reg_p3 equ r8

p751_0  equ 0FFFFFFFFFFFFFFFFh
p751_5  equ 0EEAFFFFFFFFFFFFFh
p751_6  equ 0E3EC968549F878A8h
p751_7  equ 0DA959B1A13F7CC76h
p751_8  equ 0084E9867D6EBE876h
p751_9  equ 08562B5045CB25748h
p751_10 equ 00E12909F97BADC66h
p751_11 equ 000006FE5D541F71Ch

; p751 + 1
p751p1_5  equ 0EEB0000000000000h
p751p1_6  equ 0E3EC968549F878A8h
p751p1_7  equ 0DA959B1A13F7CC76h
p751p1_8  equ 0084E9867D6EBE876h
p751p1_9  equ 08562B5045CB25748h
p751p1_10 equ 00E12909F97BADC66h
p751p1_11 equ 000006FE5D541F71Ch
; p751 x 2
p751x2_0  equ 0FFFFFFFFFFFFFFFEh
p751x2_1  equ 0FFFFFFFFFFFFFFFFh
p751x2_5  equ 0DD5FFFFFFFFFFFFFh
p751x2_6  equ 0C7D92D0A93F0F151h
p751x2_7  equ 0B52B363427EF98EDh
p751x2_8  equ 0109D30CFADD7D0EDh
p751x2_9  equ 00AC56A08B964AE90h
p751x2_10 equ 01C25213F2F75B8CDh
p751x2_11 equ 00000DFCBAA83EE38h

  .code
;***********************************************************************
;  Conditional swap
;  Operation: 
;  If choice [reg_p3] = 0, leave x[reg_p1],y[reg_p2] unchanged.
;  If choice [reg_p3] = 1, set x[reg_p1],y[reg_p2] = y[reg_p2],x[reg_p1].
;*********************************************************************** 
cswap751_asm proc
  push   rbx
  push   rdi
  push   rsi

  movzx  rax, r8b ; Get the lower 8 bits of r8 (reg_p3)
  neg    rax

  mov    rbx, [reg_p1] ; rbx = x[0]
  mov    rdi, [reg_p2] ; rdi = y[0]
  mov    rsi, rdi      ; rsi = y[0]
  xor    rsi, rbx      ; rsi = y[0] ^ x[0]
  and    rsi, rax      ; rsi = (y[0] ^ x[0]) & mask
  xor    rbx, rsi      ; rbx = (y[0] ^ x[0]) & mask) ^ y[0] = x[0] or y[0]
  xor    rdi, rsi      ; rdi = (y[0] ^ x[0]) & mask) ^ y[0] = y[0] or x[0]
  mov    [reg_p1], rbx
  mov    [reg_p2], rdi

  mov    rbx, [reg_p1+8]
  mov    rdi, [reg_p2+8]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+8], rbx
  mov    [reg_p2+8], rdi

  mov    rbx, [reg_p1+16]
  mov    rdi, [reg_p2+16]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+16], rbx
  mov    [reg_p2+16], rdi

  mov    rbx, [reg_p1+24]
  mov    rdi, [reg_p2+24]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+24], rbx
  mov    [reg_p2+24], rdi

  mov    rbx, [reg_p1+32]
  mov    rdi, [reg_p2+32]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+32], rbx
  mov    [reg_p2+32], rdi

  mov    rbx, [reg_p1+40]
  mov    rdi, [reg_p2+40]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+40], rbx
  mov    [reg_p2+40], rdi

  mov    rbx, [reg_p1+48]
  mov    rdi, [reg_p2+48]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+48], rbx
  mov    [reg_p2+48], rdi

  mov    rbx, [reg_p1+56]
  mov    rdi, [reg_p2+56]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+56], rbx
  mov    [reg_p2+56], rdi

  mov    rbx, [reg_p1+64]
  mov    rdi, [reg_p2+64]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+64], rbx
  mov    [reg_p2+64], rdi

  mov    rbx, [reg_p1+72]
  mov    rdi, [reg_p2+72]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+72], rbx
  mov    [reg_p2+72], rdi

  mov    rbx, [reg_p1+80]
  mov    rdi, [reg_p2+80]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+80], rbx
  mov    [reg_p2+80], rdi

  mov    rbx, [reg_p1+88]
  mov    rdi, [reg_p2+88]
  mov    rsi, rdi
  xor    rsi, rbx
  and    rsi, rax
  xor    rbx, rsi
  xor    rdi, rsi
  mov    [reg_p1+88], rbx
  mov    [reg_p2+88], rdi

  pop    rsi
  pop    rdi
  pop    rbx
  ret
cswap751_asm endp

;***********************************************************************
;  Conditional assign
;  Operation: If choice [reg_p3] = 0, leave x [reg_p1] unchanged. 
;             If choice [reg_p3] = 1, set x [reg_p1] = y [reg_p2].
;*********************************************************************** 
cassign751_asm proc
  push   rbx
  push   rdi
  push   rsi

  movzx  rax, r8b ; Get the lower 8 bits of r8 (reg_p3)
  neg    rax

  mov    rbx, [reg_p1] ; rbx = x[0]
  mov    rdi, [reg_p2] ; rdi = y[0]
  xor    rdi, rbx      ; rdi = y[0] ^ x[0]
  and    rdi, rax      ; rdi = (y[0] ^ x[0]) & mask
  xor    rdi, rbx      ; rdi = (y[0] ^ x[0]) & mask) ^ x[0]
  mov    [reg_p1], rdi ;     = x[0] or y[0]

  mov    rbx, [reg_p1+8]
  mov    rdi, [reg_p2+8]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+8], rdi

  mov    rbx, [reg_p1+16]
  mov    rdi, [reg_p2+16]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+16], rdi

  mov    rbx, [reg_p1+24]
  mov    rdi, [reg_p2+24]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+24], rdi

  mov    rbx, [reg_p1+32]
  mov    rdi, [reg_p2+32]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+32], rdi

  mov    rbx, [reg_p1+40]
  mov    rdi, [reg_p2+40]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+40], rdi

  mov    rbx, [reg_p1+48]
  mov    rdi, [reg_p2+48]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+48], rdi

  mov    rbx, [reg_p1+56]
  mov    rdi, [reg_p2+56]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+56], rdi

  mov    rbx, [reg_p1+64]
  mov    rdi, [reg_p2+64]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+64], rdi

  mov    rbx, [reg_p1+72]
  mov    rdi, [reg_p2+72]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+72], rdi

  mov    rbx, [reg_p1+80]
  mov    rdi, [reg_p2+80]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+80], rdi

  mov    rbx, [reg_p1+88]
  mov    rdi, [reg_p2+88]
  xor    rdi, rbx
  and    rdi, rax
  xor    rdi, rbx
  mov    [reg_p1+88], rdi

  pop    rsi
  pop    rdi
  pop    rbx
  ret
cassign751_asm endp

;***********************************************************************
;  Field addition
;  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
;***********************************************************************
fpadd751_asm proc
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  push   rdi
  push   rsi
  
  mov    rbx, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rdi, [reg_p1+64]
  add    rbx, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48] 
  adc    r15, [reg_p2+56]
  adc    rdi, [reg_p2+64] 
  mov    rax, [reg_p1+72]
  adc    rax, [reg_p2+72] 
  mov    [reg_p3+72], rax
  mov    rax, [reg_p1+80]
  adc    rax, [reg_p2+80] 
  mov    [reg_p3+80], rax
  mov    rax, [reg_p1+88]
  adc    rax, [reg_p2+88] 
  mov    [reg_p3+88], rax

  mov    rax, p751x2_0
  sub    rbx, rax
  mov    rax, p751x2_1
  sbb    r9, rax
  sbb    r10, rax
  sbb    r11, rax
  sbb    r12, rax
  mov    rax, p751x2_5
  sbb    r13, rax
  mov    rax, p751x2_6
  sbb    r14, rax
  mov    rax, p751x2_7
  sbb    r15, rax
  mov    rax, p751x2_8
  sbb    rdi, rax
  mov    [reg_p3], rbx
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rdi
  mov    rbx, [reg_p3+72]
  mov    r9, [reg_p3+80]
  mov    r10, [reg_p3+88]
  mov    rax, p751x2_9
  sbb    rbx, rax
  mov    rax, p751x2_10
  sbb    r9, rax
  mov    rax, p751x2_11
  sbb    r10, rax
  mov    [reg_p3+72], rbx
  mov    [reg_p3+80], r9
  mov    [reg_p3+88], r10
  mov    rax, 0
  sbb    rax, 0
  
  mov    rsi, p751x2_0
  and    rsi, rax
  mov    rbx, p751x2_1
  and    rbx, rax
  mov    r9, p751x2_5
  and    r9, rax
  mov    r10, p751x2_6
  and    r10, rax
  mov    r11, p751x2_7
  and    r11, rax
  mov    r12, p751x2_8
  and    r12, rax
  mov    r13, p751x2_9
  and    r13, rax
  mov    r14, p751x2_10
  and    r14, rax
  mov    r15, p751x2_11
  and    r15, rax
  
  mov    rax, [reg_p3]
  add    rax, rsi  
  mov    [reg_p3], rax
  mov    rax, [reg_p3+8]
  adc    rax, rbx 
  mov    [reg_p3+8], rax  
  mov    rax, [reg_p3+16]
  adc    rax, rbx 
  mov    [reg_p3+16], rax  
  mov    rax, [reg_p3+24]  
  adc    rax, rbx 
  mov    [reg_p3+24], rax 
  mov    rax, [reg_p3+32]  
  adc    rax, rbx 
  mov    [reg_p3+32], rax 
  mov    rax, [reg_p3+40]    
  adc    rax, r9 
  mov    [reg_p3+40], rax 
  mov    rax, [reg_p3+48]   
  adc    rax, r10 
  mov    [reg_p3+48], rax 
  mov    rax, [reg_p3+56]   
  adc    rax, r11  
  mov    [reg_p3+56], rax 
  mov    rax, [reg_p3+64]  
  adc    rax, r12 
  mov    [reg_p3+64], rax 
  mov    rax, [reg_p3+72]   
  adc    rax, r13 
  mov    [reg_p3+72], rax 
  mov    rax, [reg_p3+80]   
  adc    rax, r14 
  mov    [reg_p3+80], rax 
  mov    rax, [reg_p3+88]   
  adc    rax, r15
  mov    [reg_p3+88], rax 
  
  pop    rsi
  pop    rdi
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
fpadd751_asm endp

;***********************************************************************
;  Field subtraction
;  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]
;***********************************************************************
fpsub751_asm proc
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  push   rdi
  push   rsi
  
  mov    rbx, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rdi, [reg_p1+64]
  sub    rbx, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    r14, [reg_p2+48] 
  sbb    r15, [reg_p2+56]
  sbb    rdi, [reg_p2+64] 
  mov    [reg_p3], rbx
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rdi
  mov    rax, [reg_p1+72]
  sbb    rax, [reg_p2+72] 
  mov    [reg_p3+72], rax
  mov    rax, [reg_p1+80]
  sbb    rax, [reg_p2+80] 
  mov    [reg_p3+80], rax
  mov    rax, [reg_p1+88]
  sbb    rax, [reg_p2+88] 
  mov    [reg_p3+88], rax
  mov    rax, 0
  sbb    rax, 0
  
  mov    rsi, p751x2_0
  and    rsi, rax
  mov    rbx, p751x2_1
  and    rbx, rax
  mov    r9, p751x2_5
  and    r9, rax
  mov    r10, p751x2_6
  and    r10, rax
  mov    r11, p751x2_7
  and    r11, rax
  mov    r12, p751x2_8
  and    r12, rax
  mov    r13, p751x2_9
  and    r13, rax
  mov    r14, p751x2_10
  and    r14, rax
  mov    r15, p751x2_11
  and    r15, rax
  
  mov    rax, [reg_p3]
  add    rax, rsi  
  mov    [reg_p3], rax
  mov    rax, [reg_p3+8]
  adc    rax, rbx 
  mov    [reg_p3+8], rax  
  mov    rax, [reg_p3+16]
  adc    rax, rbx 
  mov    [reg_p3+16], rax  
  mov    rax, [reg_p3+24]  
  adc    rax, rbx 
  mov    [reg_p3+24], rax 
  mov    rax, [reg_p3+32]  
  adc    rax, rbx 
  mov    [reg_p3+32], rax 
  mov    rax, [reg_p3+40]    
  adc    rax, r9 
  mov    [reg_p3+40], rax 
  mov    rax, [reg_p3+48]   
  adc    rax, r10 
  mov    [reg_p3+48], rax 
  mov    rax, [reg_p3+56]   
  adc    rax, r11  
  mov    [reg_p3+56], rax 
  mov    rax, [reg_p3+64]  
  adc    rax, r12 
  mov    [reg_p3+64], rax 
  mov    rax, [reg_p3+72]   
  adc    rax, r13 
  mov    [reg_p3+72], rax 
  mov    rax, [reg_p3+80]   
  adc    rax, r14 
  mov    [reg_p3+80], rax 
  mov    rax, [reg_p3+88]   
  adc    rax, r15
  mov    [reg_p3+88], rax 
  
  pop    rsi
  pop    rdi
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
fpsub751_asm endp

;***********************************************************************
;  Integer multiplication
;  Based on Karatsuba method
;  Operation: c [reg_p3] = a [reg_p1] * b [reg_p2]
;  NOTE: a=c or b=c are not allowed
;***********************************************************************
mul751_asm proc
  push   r12
  push   r13
  push   r14
  push   rbx
  mov    rbx, reg_p3
  push   rdi
  mov    rdi, reg_p2
  push   rsi
  
  ; rbx[0-5] <- AH+AL
  xor    rax, rax
  mov    r8, [reg_p1+48]
  mov    r9, [reg_p1+56]
  mov    r10, [reg_p1+64]
  mov    r11, [reg_p1+72]
  mov    r12, [reg_p1+80]
  mov    r13, [reg_p1+88]
  add    r8, [reg_p1] 
  adc    r9, [reg_p1+8] 
  adc    r10, [reg_p1+16] 
  adc    r11, [reg_p1+24] 
  adc    r12, [reg_p1+32] 
  adc    r13, [reg_p1+40] 
  push   r15  
  mov    [rbx], r8
  mov    [rbx+8], r9
  mov    [rbx+16], r10
  mov    [rbx+24], r11
  mov    [rbx+32], r12
  mov    [rbx+40], r13
  sbb    rax, 0 
  sub    rsp, 96           ; Allocating space in stack
       
  ; rbx[6-11] <- BH+BL
  xor    rdx, rdx
  mov    r8, [rdi+48]
  mov    r9, [rdi+56]
  mov    r10, [rdi+64]
  mov    r11, [rdi+72]
  mov    r12, [rdi+80]
  mov    r13, [rdi+88]
  add    r8, [rdi] 
  adc    r9, [rdi+8] 
  adc    r10, [rdi+16] 
  adc    r11, [rdi+24] 
  adc    r12, [rdi+32] 
  adc    r13, [rdi+40] 
  mov    [rbx+48], r8
  mov    [rbx+56], r9
  mov    [rbx+64], r10
  mov    [rbx+72], r11
  mov    [rbx+80], r12
  mov    [rbx+88], r13
  sbb    rdx, 0 
  mov    [rsp+80], rax
  mov    [rsp+88], rdx
  
  ; (rsp[0-8],r10,r8,r9) <- (AH+AL)*(BH+BL)
  mov    r11, [rbx]
  mov    rax, r8 
  mul    r11
  mov    [rsp], rax        ; c0
  mov    r14, rdx
  
  xor    r15, r15
  mov    rax, r9
  mul    r11
  xor    r9, r9
  add    r14, rax
  adc    r9, rdx
  
  mov    r12, [rbx+8] 
  mov    rax, r8 
  mul    r12
  add    r14, rax
  mov    [rsp+8], r14      ; c1 
  adc    r9, rdx
  adc    r15, 0
  
  xor    r8, r8
  mov    rax, r10 
  mul    r11
  add    r9, rax
  mov    r13, [rbx+48] 
  adc    r15, rdx 
  adc    r8, 0
  
  mov    rax, [rbx+16] 
  mul    r13
  add    r9, rax
  adc    r15, rdx 
  mov    rax, [rbx+56] 
  adc    r8, 0
  
  mul    r12
  add    r9, rax
  mov    [rsp+16], r9      ; c2 
  adc    r15, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rbx+72] 
  mul    r11
  add    r15, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rbx+24] 
  mul    r13
  add    r15, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, r10 
  mul    r12
  add    r15, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r14, [rbx+16] 
  mov    rax, [rbx+56] 
  mul    r14
  add    r15, rax
  mov    [rsp+24], r15     ; c3 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rbx+80] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rbx+64] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r15, [rbx+48] 
  mov    rax, [rbx+32] 
  mul    r15
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rbx+72] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [rbx+24] 
  mov    rax, [rbx+56] 
  mul    r13
  add    r8, rax
  mov    [rsp+32], r8      ; c4 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rbx+88] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rbx+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rbx+72] 
  mul    r14
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rbx+40] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rbx+80] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r15, [rbx+32] 
  mov    rax, [rbx+56] 
  mul    r15
  add    r9, rax
  mov    [rsp+40], r9      ; c5 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rbx+64] 
  mul    r15
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rbx+88] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rbx+80] 
  mul    r14
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r11, [rbx+40] 
  mov    rax, [rbx+56] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rbx+72] 
  mul    r13
  add    r10, rax
  mov    [rsp+48], r10     ; c6 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rbx+88] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rbx+64] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rbx+80]
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rbx+72] 
  mul    r15
  add    r8, rax
  mov    [rsp+56], r8      ; c7 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rbx+72] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rbx+80] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rbx+88] 
  mul    r13
  add    r9, rax
  mov    [rsp+64], r9      ; c8 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rbx+88]
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [rbx+80] 
  mul    r11
  add    r10, rax          ; c9 
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [rbx+88] 
  mul    r11
  add    r8, rax           ; c10 
  adc    r9, rdx           ; c11 
  
  mov    rax, [rsp+88]
  mov    rdx, [rbx]
  and    r12, rax
  and    r14, rax
  and    rdx, rax
  and    r13, rax
  and    r15, rax
  and    r11, rax
  mov    rax, [rsp+48]
  add    rdx, rax
  mov    rax, [rsp+56]
  adc    r12, rax
  mov    rax, [rsp+64]
  adc    r14, rax
  adc    r13, r10
  adc    r15, r8
  adc    r11, r9
  mov    rax, [rsp+80]
  mov    [rsp+48], rdx
  mov    [rsp+56], r12
  mov    [rsp+64], r14
  mov    [rsp+72], r13
  mov    [rsp+80], r15
  mov    [rsp+88], r11
  
  mov    r8, [rbx+48]
  mov    r9, [rbx+56]
  mov    r10, [rbx+64]
  mov    r11, [rbx+72]
  mov    r12, [rbx+80]
  mov    r13, [rbx+88]
  and    r8, rax
  and    r9, rax
  and    r10, rax
  and    r11, rax
  and    r12, rax
  and    r13, rax
  mov    rax, [rsp+48]
  add    r8, rax
  mov    rax, [rsp+56]
  adc    r9, rax
  mov    rax, [rsp+64]
  adc    r10, rax
  mov    rax, [rsp+72]
  adc    r11, rax
  mov    rax, [rsp+80]
  adc    r12, rax
  mov    rax, [rsp+88]
  adc    r13, rax
  mov    [rsp+48], r8
  mov    [rsp+56], r9
  mov    [rsp+72], r11
  
  ; rbx[0-11] <- AL*BL
  mov    r11, [reg_p1]
  mov    rax, [rdi] 
  mul    r11
  xor    r9, r9
  mov    [rbx], rax        ; c0
  mov    [rsp+64], r10
  mov    r8, rdx

  mov    rax, [rdi+8]
  mul    r11
  xor    r10, r10
  add    r8, rax
  mov    [rsp+80], r12
  adc    r9, rdx

  mov    r12, [reg_p1+8] 
  mov    rax, [rdi] 
  mul    r12
  add    r8, rax
  mov    [rbx+8], r8       ; c1 
  adc    r9, rdx
  mov    [rsp+88], r13
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rdi+16] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [rdi] 
  mov    rax, [reg_p1+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+8] 
  mul    r12
  add    r9, rax
  mov    [rbx+16], r9      ; c2 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rdi+24] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p1+24] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+16] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r14, [reg_p1+16] 
  mov    rax, [rdi+8] 
  mul    r14
  add    r10, rax
  mov    [rbx+24], r10     ; c3 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rdi+32] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+16] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p1+32] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+24] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [rdi+8] 
  mul    r13
  add    r8, rax
  mov    [rbx+32], r8      ; c4 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rdi+40] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+24] 
  mul    r14
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r11, [reg_p1+40] 
  mov    rax, [rdi] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+32] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r15, [reg_p1+32] 
  mov    rax, [rdi+8] 
  mul    r15
  add    r9, rax
  mov    [rbx+40], r9      ; c5 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rdi+16] 
  mul    r15
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+40] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+32] 
  mul    r14
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+8] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+24] 
  mul    r13
  add    r10, rax
  mov    [rbx+48], r10     ; c6 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rdi+40] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+16] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+32]
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+24] 
  mul    r15
  add    r8, rax
  mov    [rbx+56], r8      ; c7 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rdi+24] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+32] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+40] 
  mul    r13
  add    r9, rax
  mov    [rbx+64], r9     ; c8 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rdi+40]
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [rdi+32] 
  mul    r11
  add    r10, rax
  mov    [rbx+72], r10     ; c9 
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [rdi+40] 
  mul    r11
  add    r8, rax
  mov    [rbx+80], r8      ; c10 
  adc    r9, rdx   
  mov    [rbx+88], r9      ; c11 

  ; rbx[12-23] <- AH*BH
  mov    r11, [reg_p1+48]
  mov    rax, [rdi+48] 
  mul    r11
  xor    r9, r9
  mov    [rbx+96], rax     ; c0
  mov    r8, rdx

  mov    rax, [rdi+56]
  mul    r11
  xor    r10, r10
  add    r8, rax
  adc    r9, rdx

  mov    r12, [reg_p1+56] 
  mov    rax, [rdi+48] 
  mul    r12
  add    r8, rax
  mov    [rbx+104], r8      ; c1 
  adc    r9, rdx
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rdi+64] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [rdi+48] 
  mov    rax, [reg_p1+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+56] 
  mul    r12
  add    r9, rax
  mov    [rbx+112], r9     ; c2 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rdi+72] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p1+72] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+64] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r14, [reg_p1+64] 
  mov    rax, [rdi+56] 
  mul    r14
  add    r10, rax
  mov    [rbx+120], r10    ; c3 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rdi+80] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+64] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r15, [reg_p1+80] 
  mov    rax, r13 
  mul    r15
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+72] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+72] 
  mov    rax, [rdi+56] 
  mul    r13
  add    r8, rax
  mov    [rbx+128], r8     ; c4 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rdi+88] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+72] 
  mul    r14
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r11, [reg_p1+88] 
  mov    rax, [rdi+48] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+80] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+56] 
  mul    r15
  add    r9, rax
  mov    [rbx+136], r9     ; c5 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rdi+64] 
  mul    r15
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+88] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+80] 
  mul    r14
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+56] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rdi+72] 
  mul    r13
  add    r10, rax
  mov    [rbx+144], r10    ; c6 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rdi+88] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+64] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+80]
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rdi+72] 
  mul    r15
  add    r8, rax
  mov    [rbx+152], r8    ; c7 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rdi+72] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+80] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+88] 
  mul    r13
  add    r9, rax
  mov    [rbx+160], r9    ; c8 
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rdi+88]
  mul    r15
  add    r10, rax
  adc    r8, rdx

  mov    rax, [rdi+80] 
  mul    r11
  add    r10, rax
  mov    [rbx+168], r10    ; c9 
  adc    r8, rdx

  mov    rax, [rdi+88] 
  mul    r11
  add    r8, rax
  mov    [rbx+176], r8     ; c10 
  adc    rdx, 0   
  mov    [rbx+184], rdx    ; c11  
      
  ; [r8-r15,rax,rdx,rcx,[rsp]] <- (AH+AL)*(BH+BL) - AL*BL 
  mov    r8,  [rsp]
  sub    r8,  [rbx] 
  mov    r9,  [rsp+8]
  sbb    r9,  [rbx+8]
  mov    r10, [rsp+16]
  sbb    r10, [rbx+16]
  mov    r11, [rsp+24]
  sbb    r11, [rbx+24] 
  mov    r12, [rsp+32]
  sbb    r12, [rbx+32]
  mov    r13, [rsp+40]
  sbb    r13, [rbx+40] 
  mov    r14, [rsp+48]
  sbb    r14, [rbx+48] 
  mov    r15, [rsp+56]
  sbb    r15, [rbx+56] 
  mov    rax, [rsp+64]
  sbb    rax, [rbx+64]
  mov    rdx, [rsp+72]
  sbb    rdx, [rbx+72] 
  mov    rcx, [rsp+80]
  sbb    rcx, [rbx+80] 
  mov    rsi, [rsp+88]
  sbb    rsi, [rbx+88] 
  mov    [rsp], rsi
      
  ; [r8-r15,rax,rdx,rcx,[rsp]] <- (AH+AL)*(BH+BL) - AL*BL - AH*BH
  mov    rsi, [rbx+96]
  sub    r8,  rsi 
  mov    rsi, [rbx+104]
  sbb    r9,  rsi
  mov    rsi, [rbx+112]
  sbb    r10, rsi
  mov    rsi, [rbx+120]
  sbb    r11, rsi 
  mov    rsi, [rbx+128]
  sbb    r12, rsi
  mov    rsi, [rbx+136]
  sbb    r13, rsi
  mov    rsi, [rbx+144]
  sbb    r14, rsi 
  mov    rsi, [rbx+152]
  sbb    r15, rsi 
  mov    rsi, [rbx+160]
  sbb    rax, rsi
  mov    rsi, [rbx+168]
  sbb    rdx, rsi
  mov    rsi, [rbx+176] 
  sbb    rcx, rsi
  mov    rsi, [rsp] 
  sbb    rsi, [rbx+184]
      
  ; Final result
  add    r8,  [rbx+48] 
  mov    [rbx+48], r8
  adc    r9,  [rbx+56]
  mov    [rbx+56], r9
  adc    r10, [rbx+64]
  mov    [rbx+64], r10
  adc    r11, [rbx+72]
  mov    [rbx+72], r11
  adc    r12, [rbx+80]
  mov    [rbx+80], r12
  adc    r13, [rbx+88]
  mov    [rbx+88], r13
  adc    r14, [rbx+96] 
  mov    [rbx+96], r14
  adc    r15, [rbx+104] 
  mov    [rbx+104], r15
  adc    rax, [rbx+112]
  mov    [rbx+112], rax
  adc    rdx, [rbx+120]
  mov    [rbx+120], rdx
  adc    rcx, [rbx+128]
  mov    [rbx+128], rcx
  adc    rsi, [rbx+136]
  mov    [rbx+136], rsi  
  mov    rax, [rbx+144]
  adc    rax, 0
  mov    [rbx+144], rax
  mov    rax, [rbx+152]
  adc    rax, 0
  mov    [rbx+152], rax
  mov    rax, [rbx+160]
  adc    rax, 0
  mov    [rbx+160], rax
  mov    rax, [rbx+168]
  adc    rax, 0
  mov    [rbx+168], rax
  mov    rax, [rbx+176]
  adc    rax, 0
  mov    [rbx+176], rax
  mov    rax, [rbx+184]
  adc    rax, 0
  mov    [rbx+184], rax
    
  add    rsp, 96           ; Restoring space in stack
  pop    rsi
  pop    rdi
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
mul751_asm endp

;***********************************************************************
;  Montgomery reduction
;  Based on comba method
;  Operation: c [reg_p2] = a [reg_p1]
;  NOTE: a=c is not allowed
;***********************************************************************
rdc751_asm proc
  push   r12
  push   r13 
  push   r14 
  push   r15
  push   rbx
  mov    rbx, reg_p2
  push   rdi

  mov    r11, [reg_p1]
  mov    rax, p751p1_5 
  mul    r11
  xor    r8, r8
  add    rax, [reg_p1+40]
  mov    [rbx+40], rax    ; z5
  adc    r8, rdx
  
  xor    r9, r9
  mov    rax, p751p1_6 
  mul    r11
  xor    r10, r10
  add    r8, rax
  adc    r9, rdx

  mov    r12, [reg_p1+8]
  mov    rax, p751p1_5 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+48]
  mov    [rbx+48], r8    ; z6
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, p751p1_7 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_6 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    r13, [reg_p1+16]
  mov    rax, p751p1_5 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+56]
  mov    [rbx+56], r9    ; z7
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, p751p1_8 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_7 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_6 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r14, [reg_p1+24]
  mov    rax, p751p1_5 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+64]
  mov    [rbx+64], r10   ; z8
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, p751p1_9 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_8 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_7 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_6 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r15, [reg_p1+32]
  mov    rax, p751p1_5 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+72]
  mov    [rbx+72], r8    ; z9
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, p751p1_10 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_9 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_8 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_7 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_6 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rdi, [rbx+40]
  mov    rax, p751p1_5 
  mul    rdi
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+80]
  mov    [rbx+80], r9    ; z10
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, p751p1_11 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_10 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_9 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_8 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_7 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_6 
  mul    rdi
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r11, [rbx+48]
  mov    rax, p751p1_5 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+88]
  mov    [rbx+88], r10    ; z11
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, p751p1_11 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_10 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_9 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_8 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_7 
  mul    rdi
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_6 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r12, [rbx+56]
  mov    rax, p751p1_5 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+96]
  mov    [rbx], r8        ; z0
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, p751p1_11 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  mov    rax, p751p1_10 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  mov    rax, p751p1_9
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  mov    rax, p751p1_8
  mul    rdi
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  mov    rax, p751p1_7
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  mov    rax, p751p1_6
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    r13, [rbx+64]
  mov    rax, p751p1_5
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+104]
  mov    [rbx+8], r9      ; z1
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, p751p1_11 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_10 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_9 
  mul    rdi
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_8 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_7 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_6 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r14, [rbx+72]
  mov    rax, p751p1_5 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+112]
  mov    [rbx+16], r10    ; z2
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, p751p1_11 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_10 
  mul    rdi
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_9 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_8 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_7 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_6 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r15, [rbx+80]
  mov    rax, p751p1_5 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+120]
  mov    [rbx+24], r8     ; z3
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, p751p1_11 
  mul    rdi
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_10 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_9 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_8 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_7 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_6 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rdi, [rbx+88]
  mov    rax, p751p1_5 
  mul    rdi
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+128]
  mov    [rbx+32], r9     ; z4
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, p751p1_11 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_10 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_9 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_8 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_7 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_6 
  mul    rdi
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+136]
  mov    [rbx+40], r10    ; z5
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, p751p1_11 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_10 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_9 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_8 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    rax, p751p1_7 
  mul    rdi
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+144]
  mov    [rbx+48], r8     ; z6
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, p751p1_11 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_10 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_9 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rax, p751p1_8 
  mul    rdi
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+152]
  mov    [rbx+56], r9     ; z7
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, p751p1_11 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_10 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    rax, p751p1_9 
  mul    rdi
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+160]
  mov    [rbx+64], r10    ; z8
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, p751p1_11 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0

  mov    rax, p751p1_10 
  mul    rdi
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+168]    ; z9
  mov    [rbx+72], r8     ; z9
  adc    r9, 0
  adc    r10, 0
  
  mov    rax, p751p1_11 
  mul    rdi
  add    r9, rax
  adc    r10, rdx
  add    r9, [reg_p1+176]    ; z10
  mov    [rbx+80], r9     ; z10
  adc    r10, 0  
  add    r10, [reg_p1+184]   ; z11
  mov    [rbx+88], r10    ; z11

  pop    rdi
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
rdc751_asm endp

;***********************************************************************
;  Strong reduce a field element in [0, 2*p) to one in [0,p)
;  Operation: a [reg_p2] = a [reg_p1] mod p
;*********************************************************************** 
srdc751_asm proc
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx

  ; Zero rax for later use.
  xor    rax, rax

  ; Load p into registers
  mov    rbx, p751_0
  ; P751_{1,2,3,4} = P751_0, so reuse RBX
  mov    r9, p751_5
  mov    r10, p751_6
  mov    r11, p751_7
  mov    r12, p751_8
  mov    r13, p751_9
  mov    r14, p751_10
  mov    r15, p751_11

  ; Set x <- x - p
  sub    [reg_p1], rbx
  sbb    [reg_p1+8], rbx
  sbb    [reg_p1+16], rbx
  sbb    [reg_p1+24], rbx
  sbb    [reg_p1+32], rbx
  sbb    [reg_p1+40], r9
  sbb    [reg_p1+48], r10
  sbb    [reg_p1+56], r11
  sbb    [reg_p1+64], r12
  sbb    [reg_p1+72], r13
  sbb    [reg_p1+80], r14
  sbb    [reg_p1+88], r15

  ; Save carry flag indicating x-p < 0 as a mask in AX
  sbb    rax, 0

  ; Conditionally add p to x if x-p < 0
  and    rbx, rax
  and    r9, rax
  and    r10, rax
  and    r11, rax
  and    r12, rax
  and    r13, rax
  and    r14, rax
  and    r15, rax

  adc    [reg_p1], rbx
  adc    [reg_p1+8], rbx
  adc    [reg_p1+16], rbx
  adc    [reg_p1+24], rbx
  adc    [reg_p1+32], rbx
  adc    [reg_p1+40], r9
  adc    [reg_p1+48], r10
  adc    [reg_p1+56], r11
  adc    [reg_p1+64], r12
  adc    [reg_p1+72], r13
  adc    [reg_p1+80], r14
  adc    [reg_p1+88], r15

  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
srdc751_asm endp

;***********************************************************************
;  751-bit multiprecision addition
;  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
;***********************************************************************
mp_add751_asm proc
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  push   rdi
  push   rsi
  
  mov    rsi, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rax, [reg_p1+64]
  mov    rbx, [reg_p1+72] 
  mov    rdi, [reg_p1+80]  
  mov    rdi, [reg_p1+88] 

  add    rsi, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48] 
  adc    r15, [reg_p2+56]
  adc    rax, [reg_p2+64] 
  adc    rbx, [reg_p2+72]
  adc    rdi, [reg_p2+80]
  adc    rdi, [reg_p2+88]

  mov    [reg_p3], rsi
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rax
  mov    [reg_p3+72], rbx
  mov    [reg_p3+80], rdi
  mov    [reg_p3+88], rdi
  
  pop    rsi
  pop    rdi
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
mp_add751_asm endp

;***********************************************************************
;  2x751-bit multiprecision addition
;  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
;***********************************************************************
mp_add751x2_asm proc
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  push   rdi
  push   rsi
  
  mov    rsi, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rax, [reg_p1+64]
  mov    rbx, [reg_p1+72] 
  mov    rdi, [reg_p1+80] 

  add    rsi, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48] 
  adc    r15, [reg_p2+56]
  adc    rax, [reg_p2+64] 
  adc    rbx, [reg_p2+72]
  adc    rdi, [reg_p2+80]

  mov    [reg_p3], rsi
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rax
  mov    [reg_p3+72], rbx
  mov    [reg_p3+80], rdi 
  mov    rax, [reg_p1+88] 
  adc    rax, [reg_p2+88]
  mov    [reg_p3+88], rax
  
  mov    rsi, [reg_p1+96]
  mov    r9, [reg_p1+104]
  mov    r10, [reg_p1+112]
  mov    r11, [reg_p1+120]
  mov    r12, [reg_p1+128]
  mov    r13, [reg_p1+136]
  mov    r14, [reg_p1+144]
  mov    r15, [reg_p1+152] 
  mov    rax, [reg_p1+160]
  mov    rbx, [reg_p1+168] 
  mov    rdi, [reg_p1+176]  
  mov    rdi, [reg_p1+184] 

  adc    rsi, [reg_p2+96] 
  adc    r9, [reg_p2+104] 
  adc    r10, [reg_p2+112] 
  adc    r11, [reg_p2+120] 
  adc    r12, [reg_p2+128] 
  adc    r13, [reg_p2+136] 
  adc    r14, [reg_p2+144] 
  adc    r15, [reg_p2+152]
  adc    rax, [reg_p2+160] 
  adc    rbx, [reg_p2+168]
  adc    rdi, [reg_p2+176]
  adc    rdi, [reg_p2+184]

  mov    [reg_p3+96], rsi
  mov    [reg_p3+104], r9
  mov    [reg_p3+112], r10
  mov    [reg_p3+120], r11
  mov    [reg_p3+128], r12
  mov    [reg_p3+136], r13
  mov    [reg_p3+144], r14
  mov    [reg_p3+152], r15
  mov    [reg_p3+160], rax
  mov    [reg_p3+168], rbx
  mov    [reg_p3+176], rdi
  mov    [reg_p3+184], rdi
  
  pop    rsi
  pop    rdi
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
mp_add751x2_asm endp

;***********************************************************************
;  2x751-bit multiprecision subtraction
;  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]. Returns borrow mask
;***********************************************************************
mp_sub751x2_asm proc
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  push   rdi
  push   rsi
  
  mov    rsi, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rax, [reg_p1+64]
  mov    rbx, [reg_p1+72] 
  mov    rdi, [reg_p1+80] 

  sub    rsi, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    r14, [reg_p2+48] 
  sbb    r15, [reg_p2+56]
  sbb    rax, [reg_p2+64] 
  sbb    rbx, [reg_p2+72]
  sbb    rdi, [reg_p2+80]

  mov    [reg_p3], rsi
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rax
  mov    [reg_p3+72], rbx
  mov    [reg_p3+80], rdi 
  mov    rax, [reg_p1+88] 
  sbb    rax, [reg_p2+88]
  mov    [reg_p3+88], rax
  
  mov    rsi, [reg_p1+96]
  mov    r9, [reg_p1+104]
  mov    r10, [reg_p1+112]
  mov    r11, [reg_p1+120]
  mov    r12, [reg_p1+128]
  mov    r13, [reg_p1+136]
  mov    r14, [reg_p1+144]
  mov    r15, [reg_p1+152] 
  mov    rax, [reg_p1+160]
  mov    rbx, [reg_p1+168] 
  mov    rdi, [reg_p1+176]  
  mov    rdi, [reg_p1+184] 

  sbb    rsi, [reg_p2+96] 
  sbb    r9, [reg_p2+104] 
  sbb    r10, [reg_p2+112] 
  sbb    r11, [reg_p2+120] 
  sbb    r12, [reg_p2+128] 
  sbb    r13, [reg_p2+136] 
  sbb    r14, [reg_p2+144] 
  sbb    r15, [reg_p2+152]
  sbb    rax, [reg_p2+160]
  sbb    rbx, [reg_p2+168]
  sbb    rdi, [reg_p2+176]
  sbb    rdi, [reg_p2+184]

  mov    [reg_p3+96], rsi
  mov    [reg_p3+104], r9
  mov    [reg_p3+112], r10
  mov    [reg_p3+120], r11
  mov    [reg_p3+128], r12
  mov    [reg_p3+136], r13
  mov    [reg_p3+144], r14
  mov    [reg_p3+152], r15
  mov    [reg_p3+160], rax 
  mov    rax, 0
  sbb    rax, 0
  mov    [reg_p3+168], rbx
  mov    [reg_p3+176], rdi
  mov    [reg_p3+184], rdi
  
  pop    rsi
  pop    rdi
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
mp_sub751x2_asm endp
  end
