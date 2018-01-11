//***********************************************************************
// SIDH: an efficient supersingular isogeny cryptography library
//
// Abstract: utility functions in x64 assembly for P751 on Linux and Mac
//***********************************************************************

.intel_syntax noprefix 

// Registers that are used for parameter passing (same as in fp_x64.S):
#define reg_p1  rdi
#define reg_p2  rsi

// Digits of 3^238 - 1
#define three238m1_0 0xEDCD718A828384F8
#define three238m1_1 0x733B35BFD4427A14
#define three238m1_2 0xF88229CF94D7CF38
#define three238m1_3 0x63C56C990C7C2AD6
#define three238m1_4 0xB858A87E8F4222C7
#define three238m1_5 0x254C9C6B525EAF5

.text
//***********************************************************************
//  Check less than 3^238
//  Operation: 
//  Set result [reg_p2] to 0 if the input [reg_p1] scalar is <= 3^238.
//*********************************************************************** 
#ifdef __APPLE__
.global _checklt238_asm
_checklt238_asm:
#else 
.global checklt238_asm
checklt238_asm:
#endif
  push   r12
  push   r13
  push   r14
  push   r15

  // Zero rax for later use.
  xor    rax, rax

  // Set [R10,...,R15] = 3^238
  movq   r10, three238m1_0
  movq   r11, three238m1_1
  movq   r12, three238m1_2
  movq   r13, three238m1_3
  movq   r14, three238m1_4
  movq   r15, three238m1_5

  // Set [R10,...,R15] = 3^238 - scalar
  sub    r10, [reg_p1]
  sbb    r11, [reg_p1+8]
  sbb    r12, [reg_p1+16]
  sbb    r13, [reg_p1+24]
  sbb    r14, [reg_p1+32]
  sbb    r15, [reg_p1+40]

  // Save borrow flag indicating 3^238 - scalar < 0 as a mask in AX
  sbb    rax, 0
  mov    [reg_p2], rax

  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret

//***********************************************************************
//  Multiply by 3.
//  Operation: 
//  Set scalar [reg_p1] = 3*scalar [reg_p1].
//*********************************************************************** 
#ifdef __APPLE__
.global _mulby3_asm
_mulby3_asm:
#else
.global mulby3_asm
mulby3_asm:
#endif
  push   r12
  push   r13
  push   r14
  push   r15

  // Set [R10,...,R15] = scalar
  mov    r10, [reg_p1]
  mov    r11, [reg_p1+8]
  mov    r12, [reg_p1+16]
  mov    r13, [reg_p1+24]
  mov    r14, [reg_p1+32]
  mov    r15, [reg_p1+40]

  // Add scalar twice to compute 3*scalar
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

  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
