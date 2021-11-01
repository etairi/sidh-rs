// This file is part of sidh-rs.
// Copyright (c) 2017 Erkan Tairi
// See LICENSE for licensing information.
//
// Author:
// - Erkan Tairi <erkan.tairi@gmail.com>
//

use core::mem::size_of;
use core::fmt::Debug;

use subtle::ConditionallySelectable;
use subtle::Choice;

#[cfg(test)]
use quickcheck::{Arbitrary,Gen};

// Macro to assign tuples, as Rust does not allow tuples as lvalue.
macro_rules! assign{
    {($v1:ident, $v2:expr) = $e:expr} =>
    {
        {
            let (v1, v2) = $e;
            $v1 = v1;
            $v2 = v2;
        }
    };
}

// X86 finite field arithmetic
const RADIX: u32 = 32;
pub const FP751_NUM_WORDS: usize = 24;
const P751_ZERO_WORDS: usize = 11;

const P751: [u32; FP751_NUM_WORDS] = [4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4004511743, 1241020584, 3823933061, 335006838, 3667237658, 3605784694, 139368551, 1555191624,	2237838596,	2545605734,	236097695, 3577870108, 28645];
const P751P1: [u32; FP751_NUM_WORDS] = [0, 0, 0, 0,	0, 0, 0, 0,	0, 0, 0, 4004511744, 1241020584, 3823933061, 335006838, 3667237658, 3605784694, 139368551,	1555191624,	2237838596,	2545605734,	236097695, 3577870108, 28645];
const P751X2: [u32; FP751_NUM_WORDS] = [4294967294,	4294967295,	4294967295,	4294967295,	4294967295,	4294967295,	4294967295,	4294967295,	4294967295,	4294967295,	4294967295,	3714056191,	2482041169,	3352898826,	670013677, 3039508020, 2916602093, 278737103, 3110383248, 180709896, 796244173,	472195391, 2860772920, 57291];

// Return 1 if x != 0, and 0 otherwise.
#[inline(always)]
fn is_digit_nonzero_ct(x: &u32) -> u32 {
    ((x | ((0 as u32).wrapping_sub(*x))) >> (RADIX-1)) as u32
}

// Return 1 if x = 0, and 0 otherwise.
#[inline(always)]
fn is_digit_zero_ct(x: &u32) -> u32 {
    (1 ^ is_digit_nonzero_ct(x)) as u32
}

// Return 1 if x < y, and 0 otherwise.
#[inline(always)]
fn is_digit_lessthan_ct(x: &u32, y: &u32) -> u32 {
    ((x ^ ((x ^ y) | ((x.wrapping_sub(*y)) ^ y))) >> (RADIX-1)) as u32
}

fn digit_x_digit(a: &u32, b: &u32, c: &mut [u32]) {
    let sizeof_u32 = size_of::<u32>() as u32;
    let mask_low  = <u32>::max_value() >> (sizeof_u32 * 4);
    let mask_high = <u32>::max_value() << (sizeof_u32 * 4);

    let al = a & mask_low;
    let ah = a >> (sizeof_u32 * 4);
    let bl = b & mask_low;
    let bh = b >> (sizeof_u32 * 4);

    let albl = al * bl;
    let albh = al * bh;
    let ahbl = ah * bl;
    let ahbh = ah * bh;
    c[0] = albl & mask_low;

    let mut res1 = albl >> (sizeof_u32 * 4);
    let mut res2 = ahbl & mask_low;
    let mut res3 = albh & mask_low;
    let mut temp = res1 + res2 + res3;
    let mut carry = temp >> (sizeof_u32 * 4);
    c[0] ^= temp << (sizeof_u32 * 4);

    res1 = ahbl >> (sizeof_u32 * 4);
    res2 = albh >> (sizeof_u32 * 4);
    res3 = ahbh & mask_low;
    temp = res1 + res2 + res3 + carry;
    c[1] = temp & mask_low;
    carry = temp & mask_high;
    c[1] ^= (ahbh & mask_high) + carry;
}

fn mul(multiplier: &u32, multiplicant: &u32, uv: &mut [u32]) {
    digit_x_digit(multiplier, multiplicant, uv);
}

fn addc(carry_in: &u32, addend1: &u32, addend2: &u32) -> (u32, u32) {
    let temp = addend1.wrapping_add(*carry_in);
    let sum = addend2.wrapping_add(temp);
    let carry_out = (is_digit_lessthan_ct(&temp, carry_in)) | is_digit_lessthan_ct(&sum, &temp);
    (carry_out, sum)
}

fn subc(borrow_in: &u32, minuend: &u32, subtrahend: &u32) -> (u32, u32) {
    let temp = minuend.wrapping_sub(*subtrahend);
    let borrow = (is_digit_lessthan_ct(minuend, subtrahend)) | (borrow_in & is_digit_zero_ct(&temp));
    let difference = temp.wrapping_sub(*borrow_in);
    let borrow_out = borrow;
    (borrow_out, difference)
}

#[inline]
pub fn fpadd751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element) {
    let mut carry: u32 = 0;

    for i in 0..FP751_NUM_WORDS {
        assign!{(carry, z.0[i]) = addc(&carry, &x.0[i], &y.0[i])};
    }

    carry = 0;
    for i in 0..FP751_NUM_WORDS {
        assign!{(carry, z.0[i]) = subc(&carry, &z.0[i], &P751X2[i])};
    }
    let mask = (0 as u32).wrapping_sub(carry);

    carry = 0;
    for i in 0..FP751_NUM_WORDS {
        assign!{(carry, z.0[i]) = addc(&carry, &z.0[i], &(P751X2[i] & mask))};
    }
}

#[inline]
pub fn fpsub751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element) {
    let mut borrow: u32 = 0;

    for i in 0..FP751_NUM_WORDS {
        assign!{(borrow, z.0[i]) = subc(&borrow, &x.0[i], &y.0[i])};
    }
    let mask = (0 as u32).wrapping_sub(borrow);

    borrow = 0;
    for i in 0..FP751_NUM_WORDS {
        assign!{(borrow, z.0[i]) = addc(&borrow, &z.0[i], &(P751X2[i] & mask))};
    }
}

pub fn mul751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751X2) {
    let mut t: u32 = 0;
    let mut u: u32 = 0;
    let mut v: u32 = 0;
    let mut UV = [0u32; 2];
    let mut carry: u32 = 0;

    for i in 0..FP751_NUM_WORDS {
        for j in 0..(i+1) {
            mul(&x.0[j], &y.0[i-j], &mut UV[..]);
            assign!{(carry, v) = addc(&0, &UV[0], &v)};
            assign!{(carry, u) = addc(&carry, &UV[1], &u)};
            t += carry;
        }
        z.0[i] = v;
        v = u;
        u = t;
        t = 0;
    }

    for i in FP751_NUM_WORDS..(2*FP751_NUM_WORDS-1) {
        for j in (i-FP751_NUM_WORDS+1)..FP751_NUM_WORDS {
            mul(&x.0[j], &y.0[i-j], &mut UV[..]);
            assign!{(carry, v) = addc(&0, &UV[0], &v)};
            assign!{(carry, u) = addc(&carry, &UV[1], &u)};
            t += carry;
        }
        z.0[i] = v;
        v = u;
        u = t;
        t = 0;
    }
    z.0[2*FP751_NUM_WORDS-1] = v;
}

pub fn rdc751(x: &Fp751X2, z: &mut Fp751Element) {
    let mut t: u32 = 0;
    let mut u: u32 = 0;
    let mut v: u32 = 0;
    let mut UV = [0u32; 2];
    let mut carry: u32 = 0;
    let mut count = P751_ZERO_WORDS;

    for i in 0..FP751_NUM_WORDS {
        z.0[i] = 0;
    }

    for i in 0..FP751_NUM_WORDS {
        for j in 0..i {
            if j < (((i+1) as u32).wrapping_sub(P751_ZERO_WORDS as u32) as usize) {
                mul(&z.0[j], &P751P1[i-j], &mut UV[..]);
                assign!{(carry, v) = addc(&0, &UV[0], &v)};
                assign!{(carry, u) = addc(&carry, &UV[1], &u)};
                t += carry;
            }
        }
        assign!{(carry, v) = addc(&0, &v, &x.0[i])};
        assign!{(carry, u) = addc(&carry, &u, &0)};

        t += carry;
        z.0[i] = v;
        v = u;
        u = t;
        t = 0;
    }

    for i in FP751_NUM_WORDS..(2*FP751_NUM_WORDS-1) {
        if count > 0 {
            count -= 1;
        }
        for j in (i-FP751_NUM_WORDS+1)..FP751_NUM_WORDS {
            if j < (FP751_NUM_WORDS-count) {
                mul(&z.0[j], &P751P1[i-j], &mut UV[..]);
                assign!{(carry, v) = addc(&0, &UV[0], &v)};
                assign!{(carry, u) = addc(&carry, &UV[1], &u)};
                t += carry;
            }
        }
        assign!{(carry, v) = addc(&0, &v, &x.0[i])};
        assign!{(carry, u) = addc(&carry, &u, &0)};

        t += carry;
        z.0[i-FP751_NUM_WORDS] = v;
        v = u;
        u = t;
        t = 0;
    }
    assign!{(carry, v) = addc(&0, &v, &x.0[2*FP751_NUM_WORDS-1])};
    z.0[FP751_NUM_WORDS-1] = v;
}

#[inline]
pub fn srdc751(x: &mut Fp751Element) {
    let mut borrow: u32 = 0;

    for i in 0..FP751_NUM_WORDS {
        assign!{(borrow, x.0[i]) = subc(&borrow, &x.0[i], &P751[i])};
    }
    let mask = (0 as u32).wrapping_sub(borrow);

    borrow = 0;
    for i in 0..FP751_NUM_WORDS {
        assign!{(borrow, x.0[i]) = addc(&borrow, &x.0[i], &(P751[i] & mask))};
    }
}

#[inline]
pub fn mp_add751(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element) {
    let mut carry: u32 = 0;

    for i in 0..FP751_NUM_WORDS {
        assign!{(carry, z.0[i]) = addc(&carry, &x.0[i], &y.0[i])};
    }
}

#[inline]
pub fn mp_add751x2(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2) {
    let mut carry: u32 = 0;

    for i in 0..(FP751_NUM_WORDS*2) {
        assign!{(carry, z.0[i]) = addc(&carry, &x.0[i], &y.0[i])};
    }
}

pub fn mp_sub751x2(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2) {
    let mut borrow: u32 = 0;

    for i in 0..(FP751_NUM_WORDS*2) {
        assign!{(borrow, z.0[i]) = subc(&borrow, &x.0[i], &y.0[i])};
    }
    let mask = (0 as u32).wrapping_sub(borrow);

    borrow = 0;
    for i in FP751_NUM_WORDS..(FP751_NUM_WORDS*2) {
        assign!{(borrow, z.0[i]) = addc(&borrow, &z.0[i], &(P751[i-FP751_NUM_WORDS] & mask))};
    }
}

pub fn checklt238(scalar: &[u8; 48], result: &mut u32) {
    let three238: [u32; 12] = [0x828384f8, 0xedcd718a, 0xd4427a14, 0x733b35bf, 0x94d7cf38, 0xf88229cf, 0xc7c2ad6, 0x63c56c99, 0x8f4222c7, 0xb858a87e, 0xb525eaf5, 0x254c9c6];
    let mut scalar_u32 = [0u32; 12];
    let mut ignored: u32 = 0;

    let mut j;
    let mut k: u32;
    for i in 0..48 {
        j = i / 4;
        k = (i % 4) as u32;
        scalar_u32[j as usize] |= (scalar[i] as u32) << (8 * k);
    }
    
    let mut borrow: u32 = 0;

    for i in 0..12 {
        assign!{(borrow, ignored) = subc(&borrow, &three238[i], &scalar_u32[i])};
    }
    let mask = (0 as u32).wrapping_sub(borrow);
    *result = mask;
}

pub fn mulby3(scalar: &mut [u8; 48]) {
    let mut scalar_u32 = [0u32; 12];

    let mut j;
    let mut k: u32;
    for i in 0..48 {
        j = i / 4;
        k = (i % 4) as u32;
        scalar_u32[j as usize] |= (scalar[i] as u32) << (8 * k);
    }

    let mut carry: u32 = 0;
    let temp = scalar_u32;
    for i in 0..12 {
        assign!{(carry, scalar_u32[i]) = addc(&carry, &scalar_u32[i], &temp[i])};
    }
    for i in 0..12 {
        assign!{(carry, scalar_u32[i]) = addc(&carry, &scalar_u32[i], &temp[i])};
    }

    for i in 0..48 {
        j = i / 4;
        k = (i % 4) as u32;
        scalar[i as usize] = (scalar_u32[j as usize] >> (8 * k)) as u8;
    }
}

#[derive(Copy, Clone)]
pub struct Fp751Element(pub (crate) [u32; FP751_NUM_WORDS]);

#[cfg(test)]
pub struct Fp751ElementDist;

impl ConditionallySelectable for Fp751Element {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes [u32; FP751_NUM_WORDS];
        for i in 0..FP751_NUM_WORDS {
            bytes[i] = u32::conditional_select(&a.0[i], &b.0[i], choice);
        }
        Fp751Element(bytes);
    }

    fn conditional_assign(&mut self, f: &Self, choice: Choice) {
        let mask = (-(choice as i32)) as u32;
        for i in 0..FP751_NUM_WORDS {
            self.0[i] ^= mask & (self.0[i] ^ f.0[i]);
        }
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
        // sage: (2*p-1).digits(2^32)[-1]
        // 57291
        //
        // This still allows generating values >= 2p, but hopefully that
        // excess is small.
        let mut rng = rand::thread_rng();
        let high_limb = rng.gen::<u32>() % 57291;

        Fp751Element([
            rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(),
            rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(),
            rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(),
            rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(),
            rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(),
            rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), high_limb
        ])
    }
}

impl Fp751Element {
    /// Construct a new zero `Fp751Element`.
    pub fn zero() -> Fp751Element {
        Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    }
    /// Given an `Fp751Element` in Montgomery form, convert to little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 94] {
        let mut bytes = [0u8; 94];
        let mut a = Fp751Element::zero();
        let mut aR = Fp751X2::zero();
        //let one = Fp751Element([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        aR.0[..FP751_NUM_WORDS].clone_from_slice(&self.0);
        //aR = self * &one;
        a = aR.reduce();       // = a mod p in [0, 2p)
        a = a.strong_reduce(); // = a mod p in [0, p)
        
        let mut j;
        let mut k: u32;
        // 4*24 = 96, but we drop the last two bytes since p is 751 < 752=94*8 bits.
        for i in 0..94 {
            j = i / 4;
            k = (i % 4) as u32;
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
        let mut k: u32;  
        for i in 0..94 {
            j = i / 4;
            k = (i % 4) as u32;
            // Rust indexes are of type usize.
            a.0[j as usize] |= (bytes[i as usize] as u32) << (8 * k);
        }

        let aRR = &a * &MONTGOMERY_RSQ; // = a*R*R
        let output = aRR.reduce();      // = a*R mod p
        output
    }
}

#[derive(Copy, Clone)]
pub struct Fp751X2(pub (crate) [u32; 2*FP751_NUM_WORDS]);

impl Debug for Fp751X2 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Fp751X2({:?})", &self.0[..])
    }
}

impl Fp751X2 {
    // Construct a zero `Fp751X2`.
    pub fn zero() -> Fp751X2 {
        Fp751X2([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    }
}

/// `(2^768) mod p`
pub const MONTGOMERY_R: Fp751Element = Fp751Element([149933, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2198863872, 928803942, 1428664804, 1062151376, 1769445311, 2891730478, 3365779378, 3523701078, 1285862457, 1964165097, 284660332, 616359394, 11611]);

/// `(2^768)^2 mod p`
pub const MONTGOMERY_RSQ: Fp751Element = Fp751Element([2645377112, 590366276, 2794865962, 3674276193, 1927544206, 1580635156, 2191714054, 4094426656, 2421131089, 1228065960, 518519937, 527654687, 3238301208, 2723106176, 3451258821, 3043768380, 1935645840, 1142805627, 1785382954, 1450437932, 288500043, 113837350, 2198806325, 16813]);
