// This file is part of sidh-rs.
// Copyright (c) 2017 Erkan Tairi
// See LICENSE for licensing information.
//
// Author:
// - Erkan Tairi <erkan.tairi@gmail.com>
//

//! This module contains finite field arithmetic functionality for SIDH, 
//! which is not part of the public API.

use core::fmt::Debug;

use core::cmp::{Eq, PartialEq};

use core::ops::{Add, AddAssign};
use core::ops::{Sub, SubAssign};
use core::ops::{Mul, MulAssign};
use core::ops::Neg;

use subtle::ConditionallySelectable;
use subtle::{Equal, slices_equal};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen, QuickCheck};
#[cfg(test)]
use rand::{Rand, Rng};

use backend;

#[cfg(target_arch = "x86")]
pub use backend::x86::fp_x86::*;
#[cfg(target_arch = "x86")]
pub type Fp751Element = backend::x86::fp_x86::Fp751Element;
#[cfg(target_arch = "x86")]
pub type Fp751X2 = backend::x86::fp_x86::Fp751X2;

#[cfg(target_arch = "x86_64")]
pub use backend::x64::fp_x64::*;
#[cfg(target_arch = "x86_64")]
pub type Fp751Element = backend::x64::fp_x64::Fp751Element;
#[cfg(target_arch = "x86_64")]
pub type Fp751X2 = backend::x64::fp_x64::Fp751X2;

//-----------------------------------------------------------------------------//
//                           Extension Field                                   //
//-----------------------------------------------------------------------------//

/// Represents an element of the extension field `F_{p^2}`.
#[derive(Copy, Clone, PartialEq)]
pub struct ExtensionFieldElement {
    /// This field element is in Montgomery form, so that the value `A` is
    /// represented by `aR mod p`.
    pub A: Fp751Element,
    /// This field element is in Montgomery form, so that the value `B` is
    /// represented by `bR mod p`.
    pub B: Fp751Element,
}

impl<'b> AddAssign<&'b ExtensionFieldElement> for ExtensionFieldElement {
    fn add_assign(&mut self, _rhs: &'b ExtensionFieldElement) {
        let result = (self as &ExtensionFieldElement) + _rhs;
        self.A = result.A;
        self.B = result.B;
    }
}

impl<'a, 'b> Add<&'b ExtensionFieldElement> for &'a ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    fn add(self, _rhs: &'b ExtensionFieldElement) -> ExtensionFieldElement {
        let a = &self.A + &_rhs.A;
        let b = &self.B + &_rhs.B;

        ExtensionFieldElement{
            A: a,
            B: b
        }
    }
}

impl <'b> SubAssign<&'b ExtensionFieldElement> for ExtensionFieldElement {
    fn sub_assign(&mut self, _rhs: &'b ExtensionFieldElement) {
        let result = (self as &ExtensionFieldElement) - _rhs;
        self.A = result.A;
        self.B = result.B;
    }
}

impl<'a, 'b> Sub<&'b ExtensionFieldElement> for &'a ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    fn sub(self, _rhs: &'b ExtensionFieldElement) -> ExtensionFieldElement {
        let a = &self.A - &_rhs.A;
        let b = &self.B - &_rhs.B;

        ExtensionFieldElement{
            A: a,
            B: b
        }
    }
}

impl<'b> MulAssign<&'b ExtensionFieldElement> for ExtensionFieldElement {
    fn mul_assign(&mut self, _rhs: &'b ExtensionFieldElement) {
        let result = (self as &ExtensionFieldElement) * _rhs;
        self.A = result.A;
        self.B = result.B;
    }
}

impl<'a, 'b> Mul<&'b ExtensionFieldElement> for &'a ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    fn mul(self, _rhs: &'b ExtensionFieldElement) -> ExtensionFieldElement {
        // Alias self, _rhs for more readable formulas.
        let a = &self.A;
        let b = &self.B;
        let c = &_rhs.A;
        let d = &_rhs.B;

        // We want to compute
        //
        // (a + bi)*(c + di) = (a*c - b*d) + (a*d + b*c)i
        //
        // Use Karatsuba's trick: note that
        //
        // (b - a)*(c - d) = (b*c + a*d) - a*c - b*d
        //
        // so (a*d + b*c) = (b-a)*(c-d) + a*c + b*d.
        //
        let ac = a * c;                               // = a*c*R*R
        let bd = b * d;                               // = b*d*R*R
        let b_minus_a = b - a;                        // = (b-a)*R
        let c_minus_d = c - d;                        // = (c-d)*R
        
        let mut ad_plus_bc = &b_minus_a * &c_minus_d; // = (b-a)*(c-d)*R*R
        ad_plus_bc += &ac;                            // = ((b-a)*(c-d) + a*c)*R*R
        ad_plus_bc += &bd;                            // = ((b-a)*(c-d) + a*c + b*d)*R*R
        let _b = ad_plus_bc.reduce();                 // = (a*d + b*c)*R mod p

        let ac_minus_bd = &ac - &bd;                  // = (a*c - b*d)*R*R
        let _a = ac_minus_bd.reduce();                // = (a*c - b*d)*R mod p  

        ExtensionFieldElement{
            A: _a,
            B: _b
        }
    }
}

impl <'a> Neg for &'a ExtensionFieldElement {
    type Output = ExtensionFieldElement;
    fn neg(self) -> ExtensionFieldElement {
        let zero = ExtensionFieldElement::zero();
        let result = &zero - (self as &ExtensionFieldElement);
        result
    }
}

impl ConditionallySelectable for ExtensionFieldElement {
    fn conditional_swap(&mut self, other: &mut ExtensionFieldElement, choice: u8) {
        (&mut self.A).conditional_swap(&mut other.A, choice);
        (&mut self.B).conditional_swap(&mut other.B, choice);
    }
}

impl Debug for ExtensionFieldElement {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "ExtensionFieldElement(A: {:?}\nB: {:?})", &self.A.0[..], &self.B.0[..])
    }
}

#[cfg(test)]
impl Arbitrary for ExtensionFieldElement {
    fn arbitrary<G: Gen>(g: &mut G) -> ExtensionFieldElement {
        let a = g.gen::<Fp751Element>();
        let b = g.gen::<Fp751Element>();
        ExtensionFieldElement{ A: a, B: b }
    }
}

#[cfg(test)]
impl Rand for ExtensionFieldElement {
    fn rand<R: Rng>(rng: &mut R) -> ExtensionFieldElement {
        let a = rng.gen::<Fp751Element>();
        let b = rng.gen::<Fp751Element>();
        ExtensionFieldElement{ A: a, B: b }
    }
}

impl ExtensionFieldElement {
    /// Construct a zero `ExtensionFieldElement`.
    pub fn zero() -> ExtensionFieldElement {
        #[cfg(target_arch = "x86_64")] 
        {
            ExtensionFieldElement{
                A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
                B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            }
        }
        #[cfg(target_arch = "x86")]  
        {
            ExtensionFieldElement{
                A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
                B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            }
        }
    }
    /// Construct a one `ExtensionFieldElement`.
    pub fn one() -> ExtensionFieldElement {
        #[cfg(target_arch = "x86_64")]  
        {
            ExtensionFieldElement{
                A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
                B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            }
        }
        #[cfg(target_arch = "x86")]  
        {
            ExtensionFieldElement{
                A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x83100000, 0x375c6c66, 0x5527b1e4, 0x3f4f24d0, 0x697797bf, 0xac5c4e2e, 0xc89db7b2, 0xd2076956, 0x4ca4b439, 0x7512c7e9, 0x10f7926c, 0x24bce5e2, 0x2d5b]),
                B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            }
        }
    }
    /// Set output to `1/x`.
    pub fn inv(&self) -> ExtensionFieldElement {
        let a = &self.A;
        let b = &self.B;

        // We want to compute
        //
        //    1          1     (a - bi)	    (a - bi)
        // -------- = -------- -------- = -----------
        // (a + bi)   (a + bi) (a - bi)   (a^2 + b^2)
        //
        // Letting c = 1/(a^2 + b^2), this is
        //
        // 1/(a+bi) = a*c - b*ci.
        //
        let mut asq = a * a;           // = a*a*R*R
        let bsq = b * b;               // = b*b*R*R
        asq = &asq + &bsq;             // = (a^2 + b^2)*R*R
        let mut asq_plus_bsq = PrimeFieldElement::zero();
        asq_plus_bsq.A = asq.reduce(); // = (a^2 + b^2)*R mod p
        // Now asq_plus_bsq = a^2 + b^2

        let asq_plus_bsq_inv = asq_plus_bsq.inv();
        let c = &asq_plus_bsq_inv.A;

        let ac = a * c;
        let _a = ac.reduce();

        let mut minus_b = Fp751Element::zero();
        minus_b = &minus_b - &b;
        let minus_bc = &minus_b * &c;
        let _b = minus_bc.reduce();

        ExtensionFieldElement{
            A: _a,
            B: _b
        }
    }
    // Set (y1, y2, y3)  = (1/x1, 1/x2, 1/x3).
    //
    // All xi, yi must be distinct.
    pub fn batch3_inv(x1: &ExtensionFieldElement, x2: &ExtensionFieldElement, x3: &ExtensionFieldElement) -> 
                 (ExtensionFieldElement, ExtensionFieldElement, ExtensionFieldElement)
    {
        let x1x2 = x1 * x2;     // x1*x2
        let mut t = &x1x2 * x3;
        t = t.inv();            // 1/(x1*x2*x3)
        let y1 = &t * x2;
        let _y1 = &y1 * x3;     // 1/x1
        let y2 = &t * x1;
        let _y2 = &y2 * x3;     // 1/x2
        let _y3 = &t * &x1x2;   // 1/x3

        (_y1, _y2, _y3)
    }
    /// Set the output to `x^2`.
    pub fn square(&self) -> ExtensionFieldElement {
        let a = &self.A;
        let b = &self.B;

        // We want to compute
	    //
	    // (a + bi)*(a + bi) = (a^2 - b^2) + 2abi
        //
        let a2 = a + a;        // = a*R + a*R = 2*a*R
        let a_plus_b = a + b;  // = a*R + b*R = (a+b)*R
        let a_minus_b = a - b; // = a*R - b*R = (a-b)*R

        let asq_minus_bsq = &a_plus_b * &a_minus_b; // = (a+b)*(a-b)*R*R = (a^2 - b^2)*R*R
        let ab2 = &a2 * b;                          // = 2*a*b*R*R                       

        let _a = asq_minus_bsq.reduce(); // = (a^2 - b^2)*R mod p
        let _b = ab2.reduce();           // = 2*a*b*R mod p

        ExtensionFieldElement{
            A: _a,
            B: _b
        }
    }
    /// Returns true if both sides are equal. Takes variable time.
    pub fn vartime_eq(&self, _rhs: &ExtensionFieldElement) -> bool {
        (&self.A == &_rhs.A) && (&self.B == &_rhs.B)
    }
    /// Convert the input to wire format.
    pub fn to_bytes(&self) -> [u8; 188] {
        let mut bytes = [0u8; 188];
        bytes[0..94].clone_from_slice(&self.A.to_bytes());
        bytes[94..188].clone_from_slice(&self.B.to_bytes());
        bytes
    }
    /// Read 188 bytes into the given `ExtensionFieldElement`.
    pub fn from_bytes(bytes: &[u8]) -> ExtensionFieldElement {
        assert!(bytes.len() >= 188, "Too short input to ExtensionFieldElement from_bytes, expected 188 bytes");
        let a = Fp751Element::from_bytes(&bytes[0..94]);
        let b = Fp751Element::from_bytes(&bytes[94..188]);
        ExtensionFieldElement{ A: a, B: b }
    }
}

//-----------------------------------------------------------------------------//
//                             Prime Field                                     //
//-----------------------------------------------------------------------------//

/// Represents an element of the prime field `F_p`.
#[derive(Copy, Clone, PartialEq)]
pub struct PrimeFieldElement {
    /// This field element is in Montgomery form, so that the value `A` is
	/// represented by `aR mod p`.
    pub A: Fp751Element
}

impl<'b> AddAssign<&'b PrimeFieldElement> for PrimeFieldElement {
    fn add_assign(&mut self, _rhs: &'b PrimeFieldElement) {
        let result = (self as &PrimeFieldElement) + _rhs;
        self.A = result.A;
    }
}

impl<'a, 'b> Add<&'b PrimeFieldElement> for &'a PrimeFieldElement {
    type Output = PrimeFieldElement;
    fn add(self, _rhs: &'b PrimeFieldElement) -> PrimeFieldElement {
        let a = &self.A + &_rhs.A;
        PrimeFieldElement{ A: a }
    }
}

impl <'b> SubAssign<&'b PrimeFieldElement> for PrimeFieldElement {
    fn sub_assign(&mut self, _rhs: &'b PrimeFieldElement) {
        let result = (self as &PrimeFieldElement) - _rhs;
        self.A = result.A;
    }
}

impl<'a, 'b> Sub<&'b PrimeFieldElement> for &'a PrimeFieldElement {
    type Output = PrimeFieldElement;
    fn sub(self, _rhs: &'b PrimeFieldElement) -> PrimeFieldElement {
        let a = &self.A - &_rhs.A;
        PrimeFieldElement{ A: a }
    }
}

impl<'b> MulAssign<&'b PrimeFieldElement> for PrimeFieldElement {
    fn mul_assign(&mut self, _rhs: &'b PrimeFieldElement) {
        let result = (self as &PrimeFieldElement) * _rhs;
        self.A = result.A;
    }
}

impl<'a, 'b> Mul<&'b PrimeFieldElement> for &'a PrimeFieldElement {
    type Output = PrimeFieldElement;
    fn mul(self, _rhs: &'b PrimeFieldElement) -> PrimeFieldElement {
        // Alias self, _rhs for more readable formulas.
        let a = &self.A;      // = a*R
        let b = &_rhs.A;      // = b*R
        let ab = a * b;       // = a*b*R*R
        let _a = ab.reduce(); // = a*b*R mod p
        
        PrimeFieldElement{ A: _a }
    }
}

impl <'a> Neg for &'a PrimeFieldElement {
    type Output = PrimeFieldElement;
    fn neg(self) -> PrimeFieldElement {
        let zero = PrimeFieldElement::zero();
        let result = &zero - (self as &PrimeFieldElement);
        result
    }
}

impl ConditionallySelectable for PrimeFieldElement {
    fn conditional_swap(&mut self, other: &mut PrimeFieldElement, choice: u8) {
        (&mut self.A).conditional_swap(&mut other.A, choice);
    }
}

impl Debug for PrimeFieldElement {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "PrimeFieldElement(A: {:?})", &self.A.0[..])
    }
}

#[cfg(test)]
impl Arbitrary for PrimeFieldElement {
    fn arbitrary<G: Gen>(g: &mut G) -> PrimeFieldElement {
        let a = g.gen::<Fp751Element>();
        PrimeFieldElement{ A: a }
    }
}

#[cfg(test)]
impl Rand for PrimeFieldElement {
    fn rand<R: Rng>(rng: &mut R) -> PrimeFieldElement {
        let a = rng.gen::<Fp751Element>();
        PrimeFieldElement{ A: a }
    }
}

impl PrimeFieldElement {
    /// Construct a zero `PrimeFieldElement`.
    pub fn zero() -> PrimeFieldElement {
        #[cfg(target_arch = "x86_64")] 
        {
            PrimeFieldElement{
                A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            }
        }
        #[cfg(target_arch = "x86")] 
        {
            PrimeFieldElement{
                A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            }
        }
    }
    /// Construct a one `PrimeFieldElement`.
    pub fn one() -> PrimeFieldElement {
        #[cfg(target_arch = "x86_64")] 
        {
            PrimeFieldElement{
                A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
            }
        }
        #[cfg(target_arch = "x86")] 
        {
            PrimeFieldElement{
                A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x83100000, 0x375c6c66, 0x5527b1e4, 0x3f4f24d0, 0x697797bf, 0xac5c4e2e, 0xc89db7b2, 0xd2076956, 0x4ca4b439, 0x7512c7e9, 0x10f7926c, 0x24bce5e2, 0x2d5b]),
            }
        }
    }
    /// Set the output to `x^2`.
    pub fn square(&self) -> PrimeFieldElement {
        let a = &self.A;      // = a*R
        let b = &self.A;      // = b*R
        let ab = a * b;       // = a*b*R*R
        let _a = ab.reduce(); // = a*b*R mod p

        PrimeFieldElement{ A: _a }
    }
    /// Raise self to `2^(2^k)`-th power, for `k >= 1`, by repeated squarings.
    fn pow2k(&self, k: u8) -> PrimeFieldElement {
        let mut result = self.square();
        for _ in 1..k { result = result.square(); }
        result
    }
    /// Set output to `x^((p-3)/4)`. If `x` is square, this is `1/sqrt(x)`.
    fn p34(&self) -> PrimeFieldElement {
        // Sliding-window strategy computed with Sage, awk, sed, and tr.
        //
        // This performs sum(powStrategy) = 744 squarings and len(mulStrategy)
        // = 137 multiplications, in addition to 1 squaring and 15
        // multiplications to build a lookup table.
        //
        // In total this is 745 squarings, 152 multiplications.  Since squaring
        // is not implemented for the prime field, this is 897 multiplications
        // in total.
        let pow_strategy: [u8; 137] = [5, 7, 6, 2, 10, 4, 6, 9, 8, 5, 9, 4, 7, 5, 5, 4, 8, 3, 9, 5, 5, 4, 10, 4, 6, 6, 6, 5, 8, 9, 3, 4, 9, 4, 5, 6, 6, 2, 9, 4, 5, 5, 5, 7, 7, 9, 4, 6, 4, 8, 5, 8, 6, 6, 2, 9, 7, 4, 8, 8, 8, 4, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 2];
        let mul_strategy: [u8; 137] = [31, 23, 21, 1, 31, 7, 7, 7, 9, 9, 19, 15, 23, 23, 11, 7, 25, 5, 21, 17, 11, 5, 17, 7, 11, 9, 23, 9, 1, 19, 5, 3, 25, 15, 11, 29, 31, 1, 29, 11, 13, 9, 11, 27, 13, 19, 15, 31, 3, 29, 23, 31, 25, 11, 1, 21, 19, 15, 15, 21, 29, 13, 23, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 3];
        let initial_mul: u8 = 27;

        // Build a lookup table of odd multiples of x.
        let mut lookup = [PrimeFieldElement::zero(); 16];
        let xx: &PrimeFieldElement = &self.square(); // Set xx = x^2
        lookup[0] = *self;

        for i in 1..16 {
            lookup[i as usize] = &lookup[(i-1) as usize] * xx;
        }
        // Now lookup = {x, x^3, x^5, ... }
	    // so that lookup[i] = x^{2*i + 1}
	    // so that lookup[k/2] = x^k, for odd k
        let mut result = lookup[(initial_mul / 2) as usize];
        for i in 0..137 {
            result = result.pow2k(pow_strategy[i]);
            result = &result * &lookup[(mul_strategy[i] / 2) as usize];
        }
        result
    }
    /// Set output to `sqrt(x)`, if x is a square. If `x` is nonsquare output is undefined.
    fn sqrt(&self) -> PrimeFieldElement {
        let mut result = self.p34(); // result = (y^2)^((p-3)/4) = y^((p-3)/2)
        result = &result * self;     // result = y^2 * y^((p-3)/2) = y^((p+1)/2)
        // Now result^2 = y^(p+1) = y^2 = x, so result = sqrt(x).
        result
    }
    /// Set output to `1/x`.
    pub fn inv(&self) -> PrimeFieldElement {
        let mut result = self.square(); // result = x^2
        result = result.p34();          // result = (x^2)^((p-3)/4) = x^((p-3)/2)
        result = result.square();       // result = x^(p-3)
        result = &result * self;        // result = x^(p-2)
        result
    }
    /// Returns true if both sides are equal. Takes variable time.
    pub fn vartime_eq(&self, _rhs: &PrimeFieldElement) -> bool {
        &self.A == &_rhs.A
    }
}

//-----------------------------------------------------------------------------//
//                              Internals                                      //
//-----------------------------------------------------------------------------//

impl<'b> AddAssign<&'b Fp751Element> for Fp751Element {
    fn add_assign(&mut self, _rhs: &'b Fp751Element) {
        let result = (self as &Fp751Element) + _rhs;
        self.0 = result.0
    }
}

impl<'a, 'b> Add<&'b Fp751Element> for &'a Fp751Element {
    type Output = Fp751Element;
    fn add(self, _rhs: &'b Fp751Element) -> Fp751Element {
        let mut result = Fp751Element::zero();
        fpadd751(&self, _rhs, &mut result);
        result
    }
}

impl <'b> SubAssign<&'b Fp751Element> for Fp751Element {
    fn sub_assign(&mut self, _rhs: &'b Fp751Element) {
        let result = (self as &Fp751Element) - _rhs;
        self.0 = result.0
    }
}

impl<'a, 'b> Sub<&'b Fp751Element> for &'a Fp751Element {
    type Output = Fp751Element;
    fn sub(self, _rhs: &'b Fp751Element) -> Fp751Element {
        let mut result = Fp751Element::zero();
        fpsub751(&self, _rhs, &mut result);
        result
    }
}

impl<'a, 'b> Mul<&'b Fp751Element> for &'a Fp751Element {
    type Output = Fp751X2;
    fn mul(self, _rhs: &'b Fp751Element) -> Fp751X2 {
        let mut result = Fp751X2::zero();
        mul751(&self, _rhs, &mut result); // = a*c*R*R
        result
    }
}

impl <'a> Neg for &'a Fp751Element {
    type Output = Fp751Element;
    fn neg(self) -> Fp751Element {
        let zero = Fp751Element::zero();
        let result = &zero - (self as &Fp751Element);
        result
    }
}

impl Eq for Fp751Element {}
impl PartialEq for Fp751Element {
    /// Test equality between two `Fp751Element`s.
    /// 
    /// # Warning
    /// 
    /// This comparison is *not* constant time.
    fn eq(&self, other: &Fp751Element) -> bool {
        let mut _self = *self;
        let mut _other = *other;

        _self = _self.strong_reduce();
        _other = _other.strong_reduce();

        let mut eq: bool = true;
        for i in 0..FP751_NUM_WORDS {
            eq = (_self.0[i] == _other.0[i]) && eq;
        }
        eq
    }
}

impl Equal for Fp751Element {
    /// Test equality between two `Fp751Element`s.
    ///
    /// # Returns
    ///
    /// `1u8` if the two `Fp751Element`s are equal, and `0u8` otherwise.
    fn ct_eq(&self, other: &Fp751Element) -> u8 {
        slices_equal(&self.to_bytes(), &other.to_bytes())
    }
}

#[cfg(test)]
impl Arbitrary for Fp751Element {
    fn arbitrary<G: Gen>(g: &mut G) -> Fp751Element {
        g.gen::<Fp751Element>()
    }
}

impl Fp751Element {
    /// Reduce a field element in `[0, 2*p)` to one in `[0,p)`.
    pub fn strong_reduce(&self) -> Fp751Element {
        let mut _self = *self;
        srdc751(&mut _self);
        _self
    }
}

impl<'b> AddAssign<&'b Fp751X2> for Fp751X2 {
    fn add_assign(&mut self, _rhs: &'b Fp751X2) {
        let result = (self as &Fp751X2) + _rhs;
        self.0 = result.0
    }
}

impl<'a, 'b> Add<&'b Fp751X2> for &'a Fp751X2 {
    type Output = Fp751X2;
    fn add(self, _rhs: &'b Fp751X2) -> Fp751X2 {
        let mut result = Fp751X2::zero();
        mp_add751x2(&self, _rhs, &mut result);
        result
    }
}

impl <'b> SubAssign<&'b Fp751X2> for Fp751X2 {
    fn sub_assign(&mut self, _rhs: &'b Fp751X2) {
        let result = (self as &Fp751X2) - _rhs;
        self.0 = result.0
    }
}

impl<'a, 'b> Sub<&'b Fp751X2> for &'a Fp751X2 {
    type Output = Fp751X2;
    fn sub(self, _rhs: &'b Fp751X2) -> Fp751X2 {
        let mut result = Fp751X2::zero();
        mp_sub751x2(&self, _rhs, &mut result);
        result
    }
}

impl Fp751X2 {
    /// Perform Montgomery reduction, `x R^{-1} (mod p)`.
    pub fn reduce(&self) -> Fp751Element {
        let mut result = Fp751Element::zero();
        rdc751(self, &mut result);
        result
    }
}

pub fn checklt238(scalar: &[u8; 48], result: &mut u32) {
    #[cfg(target_arch = "x86_64")]
    backend::x64::fp_x64::checklt238(scalar, result);
    #[cfg(target_arch = "x86")]
    backend::x86::fp_x86::checklt238(scalar, result);
}

pub fn mulby3(scalar: &mut [u8; 48]) {
    #[cfg(target_arch = "x86_64")]
    backend::x64::fp_x64::mulby3(scalar);
    #[cfg(target_arch = "x86")]
    backend::x86::fp_x86::mulby3(scalar);
}

#[cfg(test)]
mod test {
    use super::*;

    const SCALE_FACTOR: u8 = 3;
    const MAX_TESTS: u64 = 1 << (10 + SCALE_FACTOR);

    #[test]
    fn one_extension_field_to_byte() {
        let one = &ExtensionFieldElement::one();
        let bytes = one.to_bytes();

        assert_eq!(bytes[0], 1);

        for i in 1..188 {
            assert_eq!(bytes[i], 0);
        }
    }
    
    #[test]
    fn extension_field_element_to_bytes_round_trip() {
        fn round_trips(x: ExtensionFieldElement) -> bool {
            let bytes = x.to_bytes();
            let x_prime = ExtensionFieldElement::from_bytes(&bytes);
            x.vartime_eq(&x_prime)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(round_trips as fn(ExtensionFieldElement) -> bool);
    }

    #[test]
    fn extension_field_element_mul_distributes_over_add() {
        fn mul_distributes_over_add(x: ExtensionFieldElement, y: ExtensionFieldElement, z: ExtensionFieldElement) -> bool {
            // Compute t1 = (x+y)*z
            let t1 = &(&x + &y) * &z;
            // Compute t2 = x*z + y*z
            let t2 = &(&x * &z) + &(&y * &z);

            t1.vartime_eq(&t2)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(mul_distributes_over_add as fn(ExtensionFieldElement, ExtensionFieldElement, ExtensionFieldElement) -> bool);
    }

    #[test]
    fn extension_field_element_mul_is_associative() {
        fn is_associative(x: ExtensionFieldElement, y: ExtensionFieldElement, z: ExtensionFieldElement) -> bool {
            // Compute t1 = (x*y)*z
            let t1 = &(&x * &y) * &z;
            // Compute t2 = (y*z)*x
            let t2 = &(&y * &z) * &x;

            t1.vartime_eq(&t2)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(is_associative as fn(ExtensionFieldElement, ExtensionFieldElement, ExtensionFieldElement) -> bool);
    }

    #[test]
    fn extension_field_element_square_matches_mul() {
        fn square_matches_mul(x: ExtensionFieldElement) -> bool {
            // Compute t1 = (x*x)
            let t1 = &x * &x;
            // Compute t2 = x^2
            let t2 = x.square();

            t1.vartime_eq(&t2)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(square_matches_mul as fn(ExtensionFieldElement) -> bool);
    }

    #[test]
    fn extension_field_element_inv() {
        fn inverse(x: ExtensionFieldElement) -> bool {
            let mut z = x.inv();
            // Now z = (1/x), so (z * x) * x == x
            z = &(&z * &x) * &x;

            z.vartime_eq(&x)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(inverse as fn(ExtensionFieldElement) -> bool);
    }

    #[test]
    fn extension_field_element_batch3_inv() {
        fn batch_inverse(x1: ExtensionFieldElement, x2: ExtensionFieldElement, x3: ExtensionFieldElement) -> bool {
            let x1_inv = x1.inv();
            let x2_inv = x2.inv();
            let x3_inv = x3.inv();

            let (y1, y2, y3) = ExtensionFieldElement::batch3_inv(&x1, &x2, &x3);

            y1.vartime_eq(&x1_inv) && y2.vartime_eq(&x2_inv) && y3.vartime_eq(&x3_inv)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(batch_inverse as fn(ExtensionFieldElement, ExtensionFieldElement, ExtensionFieldElement) -> bool);
    }

    #[test]
    fn prime_field_element_inv() {
        fn inverse(x: PrimeFieldElement) -> bool {
            let mut z = x.inv();
            // Now z = (1/x), so (z * x) * x == x
            z = &(&z * &x) * &x;

            z.vartime_eq(&x)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(inverse as fn(PrimeFieldElement) -> bool);
    }

    #[test]
    fn prime_field_element_sqrt() {
        fn square_root(x: PrimeFieldElement) -> bool {
            // Construct y = x^2 so we're sure y is square.
            let y = x.square();
            let mut z = y.sqrt();
            // Now z = sqrt(y), so z^2 == y
            z = z.square();

            z.vartime_eq(&y)
        }
        QuickCheck::new().max_tests(MAX_TESTS)
                         .quickcheck(square_root as fn(PrimeFieldElement) -> bool);
    }

    #[test]
    fn fp751_element_conditional_swap() {
        let one: Fp751Element;
        let two: Fp751Element;

        #[cfg(target_arch = "x86_64")]  
        {
            one = Fp751Element([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
            two = Fp751Element([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
        }
        #[cfg(target_arch = "x86")] 
        {
            one = Fp751Element([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
            two = Fp751Element([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);          
        }

        let mut x = one;
        let mut y = two;

        x.conditional_swap(&mut y, 0);
        assert_eq!(x, one); 
        assert_eq!(y, two);

        x.conditional_swap(&mut y, 1);
        assert_eq!(x, two);
        assert_eq!(y, one);
    }

    // #[test]
    // fn fp751_element_conditional_assign() {
    //     let mut one: Fp751Element;
    //     let mut two: Fp751Element;

    //     #[cfg(target_arch = "x86_64")] 
    //     {
    //         one = Fp751Element([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    //         two = Fp751Element([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    //     }
    //     #[cfg(target_arch = "x86")]  
    //     {
    //         one = Fp751Element([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    //         two = Fp751Element([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);          
    //     }

    //     one.conditional_assign(&two, 0);
    //     assert_ne!(one, two);

    //     one.conditional_assign(&two, 1);
    //     assert_eq!(one, two);
    // }
}

#[cfg(all(test, feature = "bench"))]
mod bench {
    use super::*;
    use test::Bencher;
    
    #[cfg(target_arch = "x86_64")]
    static BENCH_X: Fp751Element = Fp751Element([17026702066521327207, 5108203422050077993, 10225396685796065916, 11153620995215874678, 6531160855165088358, 15302925148404145445, 1248821577836769963, 9789766903037985294, 7493111552032041328, 10838999828319306046, 18103257655515297935, 27403304611634]);
    #[cfg(target_arch = "x86_64")]
    static BENCH_Y: Fp751Element = Fp751Element([4227467157325093378, 10699492810770426363, 13500940151395637365, 12966403950118934952, 16517692605450415877, 13647111148905630666, 14223628886152717087, 7167843152346903316, 15855377759596736571, 4300673881383687338, 6635288001920617779, 30486099554235]);
    #[cfg(target_arch = "x86_64")]
    static BENCH_Z: Fp751X2 = Fp751X2([1595347748594595712, 10854920567160033970, 16877102267020034574, 12435724995376660096, 3757940912203224231, 8251999420280413600, 3648859773438820227, 17622716832674727914, 11029567000887241528, 11216190007549447055, 17606662790980286987, 4720707159513626555, 12887743598335030915, 14954645239176589309, 14178817688915225254, 1191346797768989683, 12629157932334713723, 6348851952904485603, 16444232588597434895, 7809979927681678066, 14642637672942531613, 3092657597757640067, 10160361564485285723, 240071237]);

    #[cfg(target_arch = "x86")]
    static BENCH_X: Fp751Element = Fp751Element([1936311911, 3964338001, 2881146153, 1189346290, 4166304380, 2380785691, 1663982198, 2596904755, 3071095398, 1520654385, 386227493, 3562989912, 3335369387, 290763931, 1098154510, 2279357729, 2705254768, 1744625985, 2541617470, 2523651306, 710686863, 4214993132, 1413263154, 6380]);
    #[cfg(target_arch = "x86")]
    static BENCH_Y: Fp751Element = Fp751Element([1140726274, 984283899, 3872467451, 2491169797, 1639897205, 3143432585, 2500827560, 3018976177, 16248581, 3845825001, 3502967754, 3177465672, 2820547359, 3311696668, 3311039252, 1668893534, 610562107, 3691617809, 4071412906, 1001328667, 1357106483, 1544898376, 421687227, 7098]);
    #[cfg(target_arch = "x86")]
    static BENCH_Z: Fp751X2 = Fp751X2([674445184, 371445843, 1990709938, 2527358142, 3618325006, 3929506583, 4192157312, 2895417854, 1724372135, 874963801, 1955274144, 1921318336, 2802352003, 849566369, 350210026, 4103108503, 172043064, 2568021184, 3443870607, 2611472738, 947370507, 4099370630, 1936979899, 1099125286, 1058207363, 3000661637, 2803593213, 3481899676, 3268487846, 3301263248, 3176258547, 277382041, 824052603, 2940454970, 2825566947, 1478207286, 4282423823, 3828721257, 2087041778, 1818402653, 780006429, 3409254754, 373411203, 720065459, 3501029211, 2365643522, 240071237, 0]);

    #[bench]
    fn extension_field_element_add(b: &mut Bencher) {
        let z = ExtensionFieldElement{ A: BENCH_X, B: BENCH_Y };
        b.iter(|| &z + &z);
    }

    #[bench]
    fn extension_field_element_sub(b: &mut Bencher) {
        let z = ExtensionFieldElement{ A: BENCH_X, B: BENCH_Y };
        b.iter(|| &z - &z);
    }

    #[bench]
    fn extension_field_element_mul(b: &mut Bencher) {
        let z = ExtensionFieldElement{ A: BENCH_X, B: BENCH_Y };
        b.iter(|| &z * &z);
    }

    #[bench]
    fn extension_field_element_inv(b: &mut Bencher) {
        let z = ExtensionFieldElement{ A: BENCH_X, B: BENCH_Y };
        b.iter(|| z.inv()); 
    }

    #[bench]
    fn extension_field_element_square(b: &mut Bencher) {
        let z = ExtensionFieldElement{ A: BENCH_X, B: BENCH_Y };
        b.iter(|| z.square());
    }

    #[bench]
    fn prime_field_element_add(b: &mut Bencher) {
        let z = PrimeFieldElement{ A: BENCH_X };
        b.iter(|| &z + &z);
    }

    #[bench]
    fn prime_field_element_sub(b: &mut Bencher) {
        let z = PrimeFieldElement{ A: BENCH_X };
        b.iter(|| &z - &z);
    }

    #[bench]
    fn prime_field_element_mul(b: &mut Bencher) {
        let z = PrimeFieldElement{ A: BENCH_X };
        b.iter(|| &z * &z);
    }

    #[bench]
    fn prime_field_element_inv(b: &mut Bencher) {
        let z = PrimeFieldElement{ A: BENCH_X };
        b.iter(|| z.inv());
    }

    #[bench]
    fn prime_field_element_sqrt(b: &mut Bencher) {
        let z = PrimeFieldElement{ A: BENCH_X };
        b.iter(|| z.sqrt());
    }

    #[bench]
    fn prime_field_element_square(b: &mut Bencher) {
        let z = PrimeFieldElement{ A: BENCH_X };
        b.iter(|| z.square());
    }

    #[bench]
    fn fp751_mul(b: &mut Bencher) {
        let mut z = Fp751X2::zero();
        b.iter(|| mul751(&BENCH_X, &BENCH_Y, &mut z));
    }

    #[bench]
    fn fp751_rdc(b: &mut Bencher) {
        let mut z = Fp751Element::zero();
        b.iter(|| rdc751(&BENCH_Z, &mut z));
    }

    #[bench]
    fn fp751_add(b: &mut Bencher) {
        let mut z = Fp751Element::zero();
        b.iter(|| fpadd751(&BENCH_X, &BENCH_Y, &mut z));
    }

    #[bench]
    fn fp751_sub(b: &mut Bencher) {
        let mut z = Fp751Element::zero();
        b.iter(|| fpsub751(&BENCH_X, &BENCH_Y, &mut z));
    }
}
