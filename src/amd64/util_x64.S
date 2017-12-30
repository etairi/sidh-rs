//*******************************************************************************************
// SIDH: an efficient supersingular isogeny cryptography library
//
// Abstract: utility functions in x64 assembly for P751 on Linux
//*******************************************************************************************

.intel_syntax noprefix 

// Registers that are used for parameter passing (same as in fp_x64.S):
#define reg_p1  rdi
#define reg_p2  rsi

// Digits of 3^238 - 1
#define three238m1_0 0xedcd718a828384f8
#define three238m1_1 0x733b35bfd4427a14
#define three238m1_2 0xf88229cf94d7cf38
#define three238m1_3 0x63c56c990c7c2ad6
#define three238m1_4 0xb858a87e8f4222c7
#define three238m1_5 0x254c9c6b525eaf5

.text
//***********************************************************************
//  Check less than 3^238
//  Operation: 
//  Set result [reg_p2] to 0 if the input [reg_p1] scalar is <= 3^238.
//*********************************************************************** 
.global checklt238_asm
checklt238_asm:
  push   r12
  push   r13

  // Zero rax for later use.
  xor    rax, rax

  // Set [R10,...,R15] = 3^238
  mov    r10, three238m1_0
  mov    r11, three238m1_1
  mov    r12, three238m1_2
  mov    r13, three238m1_3
  mov    r14, three238m1_4
  mov    r15, three238m1_5

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

  pop    r13
  pop    r12
  ret

//***********************************************************************
//  Multiply by 3.
//  Operation: 
//  Set scalar [reg_p1] = 3*scalar [reg_p1].
//*********************************************************************** 
.global mulby3_asm
mulby3_asm:
  push   r12
  push   r13

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

  pop    r13
  pop    r12
  ret
