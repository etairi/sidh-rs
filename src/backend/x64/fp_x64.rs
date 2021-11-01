// This file is part of sidh-rs.
// Copyright (c) 2017 Erkan Tairi
// See LICENSE for licensing information.
//
// Author:
// - Erkan Tairi <erkan.tairi@gmail.com>
//

use core::fmt::Debug;

use subtle::ConditionallySelectable;
use subtle::Choice;

#[cfg(test)]
use quickcheck::{Arbitrary,Gen};

pub const FP751_NUM_WORDS: usize = 12;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Fp751Element(pub (crate) [u64; FP751_NUM_WORDS]);

#[cfg(test)]
pub struct Fp751ElementDist;

impl ConditionallySelectable for Fp751Element {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u64; FP751_NUM_WORDS];
        for i in 0..FP751_NUM_WORDS {
            bytes[i] = u64::conditional_select(&a.0[i], &b.0[i], choice);
        }

        Fp751Element(bytes)
    }

    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        unsafe { cswap751_asm(a, b, choice); }
    }
}

impl Debug for Fp751Element {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Fp751Element({:?})", &self.0[..])
    }
}

#[cfg(test)]
impl Arbitrary for Fp751Element {
    fn arbitrary(g: &mut Gen) -> Fp751Element {
        // Generation strategy: low limbs taken from [0,2^64), high limb
        // taken from smaller range.
        //
        // Field elements taken in range [0,2p). Emulate this by capping
        // the high limb by the top digit of 2*p-1:
        //
        // sage: (2*p-1).digits(2^64)[-1]
        // 246065832128056
        //
        // This still allows generating values >= 2p, but hopefully that
        // excess is small.
        let mut rng = rand::thread_rng();
        let high_limb = rng.gen::<u64>() % 246065832128056;

        Fp751Element([
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            high_limb
        ])
    }
}

impl Fp751Element {
    // Construct a new zero `Fp751Element`.
    pub fn zero() -> Fp751Element {
        Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    }
    /// Given an `Fp751Element` in Montgomery form, convert to little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 94] {
        let mut bytes = [0u8; 94];
        let mut a = Fp751Element::zero();
        let mut aR = Fp751X2::zero();

        aR.0[..FP751_NUM_WORDS].clone_from_slice(&self.0);
        a = aR.reduce();       // = a mod p in [0, 2p)
        a = a.strong_reduce(); // = a mod p in [0, p)

        let mut j;
        let mut k: u64;
        // 8*12 = 96, but we drop the last two bytes since p is 751 < 752=94*8 bits.
        for i in 0..94 {
            j = i / 8;
            k = (i % 8) as u64;
            // Rust indexes are of type usize.
            bytes[i as usize] = (a.0[j as usize] >> (8 * k)) as u8;
        }
        bytes
    }
    /// Read an `Fp751Element` from little-endian bytes and convert to Montgomery form.
    pub fn from_bytes(bytes: &[u8]) -> Fp751Element {
        assert!(bytes.len() >= 94, "Too short input to Fp751Element from_bytes, expected 94 bytes");

        let mut a = Fp751Element::zero();
        let mut j;
        let mut k: u64;  
        for i in 0..94 {
            j = i / 8;
            k = (i % 8) as u64;
            // Rust indexes are of type usize.
            a.0[j as usize] |= (bytes[i as usize] as u64) << (8 * k);
        }

        let aRR = &a * &MONTGOMERY_RSQ; // = a*R*R
        let output = aRR.reduce();      // = a*R mod p
        output
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub struct Fp751X2(pub (crate) [u64; 2*FP751_NUM_WORDS]);

impl Debug for Fp751X2 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Fp751X2({:?})", &self.0[..])
    }
}

impl Fp751X2 {
    // Construct a zero `Fp751X2`.
    pub fn zero() -> Fp751X2 {
        Fp751X2([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    }
}

/// `(2^768) mod p`
pub const MONTGOMERY_R: Fp751Element = Fp751Element([149933, 0, 0, 0, 0, 9444048418595930112, 6136068611055053926, 7599709743867700432, 14455912356952952366, 5522737203492907350, 1222606818372667369, 49869481633250]);

/// `(2^768)^2 mod p`
pub const MONTGOMERY_RSQ: Fp751Element = Fp751Element([2535603850726686808, 15780896088201250090, 6788776303855402382, 17585428585582356230, 5274503137951975249, 2266259624764636289, 11695651972693921304, 13072885652150159301, 4908312795585420432, 6229583484603254826, 488927695601805643, 72213483953973]);

extern {
    // If choice = 1, set x,y = y,x. Otherwise, leave x,y unchanged.
    // This function executes in constant time.
    #[no_mangle]
    fn cswap751_asm(x: &mut Fp751Element, y: &mut Fp751Element, choice: Choice);
    // If choice = 1, assign y to x. Otherwise, leave x unchanged.
    // This function executes in constant time.
    #[no_mangle]
    fn cassign751_asm(x: &mut Fp751Element, y: &Fp751Element, choice: u8);
    // Compute z = x + y (mod p).
    #[no_mangle]
    fn fpadd751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element);
    // Compute z = x - y (mod p).
    #[no_mangle]
    fn fpsub751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element);
    // Compute z = x * y.
    #[no_mangle]
    fn mul751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751X2);
    // Perform Montgomery reduction: set z = x R^{-1} (mod p).
    #[no_mangle]
    fn rdc751_asm(x: &Fp751X2, z: &mut Fp751Element);
    // Reduce a field element in [0, 2*p) to one in [0,p).
    #[no_mangle]
    fn srdc751_asm(x: &mut Fp751Element);
    // Compute z = x + y, without reducing mod p.
    #[no_mangle]
    fn mp_add751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element);
    // Compute z = x + y, without reducing mod p.
    #[no_mangle]
    fn mp_add751x2_asm(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2);
    // Compute z = x - y, without reducing mod p.
    #[no_mangle]
    fn mp_sub751x2_asm(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2);
    // Set result to zero if the input scalar is <= 3^238.
    #[no_mangle]
    fn checklt238_asm(scalar: &[u8; 48], result: &mut u32);
    // Set scalar = 3*scalar.
    #[no_mangle]
    fn mulby3_asm(scalar: &mut [u8; 48]);
}

pub fn fpadd751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element) {
    unsafe { fpadd751_asm(x, y, z); }
}

pub fn fpsub751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element) {
    unsafe { fpsub751_asm(x, y, z); }
}

pub fn mul751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751X2) {
    unsafe { mul751_asm(x, y, z); }
}

pub fn rdc751(x: &Fp751X2, z: &mut Fp751Element) {
    unsafe { rdc751_asm(x, z); }
}

pub fn srdc751(x: &mut Fp751Element) {
    unsafe { srdc751_asm(x); }
}

pub fn mp_add751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element) {
    unsafe { mp_add751_asm(x, y, z); }
}

pub fn mp_add751x2(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2) {
    unsafe { mp_add751x2_asm(x, y, z); }
}

pub fn mp_sub751x2(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2) {
    unsafe { mp_sub751x2_asm(x, y, z); }
}

pub fn checklt238(scalar: &[u8; 48], result: &mut u32) {
    unsafe { checklt238_asm(scalar, result); }
}

pub fn mulby3(scalar: &mut [u8; 48]) {
    unsafe { mulby3_asm(scalar); }
}
