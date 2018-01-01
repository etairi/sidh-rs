use core::fmt::Debug;

use core::cmp::{Eq, PartialEq};

use core::ops::{Add, AddAssign};
use core::ops::{Sub, SubAssign};
use core::ops::{Mul, MulAssign};
use core::ops::Neg;

// NOTE: We do not use conditional assign (for now).
//use subtle::ConditionallyAssignable;
use subtle::ConditionallySwappable;
use subtle::Equal;
use subtle::slices_equal;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen, QuickCheck};
#[cfg(test)]
use rand::{Rand, Rng};

//-----------------------------------------------------------------------------//
//                           Extension Field                                   //
//-----------------------------------------------------------------------------//

// Represents an element of the extension field F_{p^2}.
#[derive(Copy, Clone, PartialEq)]
pub struct ExtensionFieldElement {
    // This field element is in Montgomery form, so that the value `A` is
    // represented by `aR mod p`.
    pub A: Fp751Element,
    // This field element is in Montgomery form, so that the value `B` is
    // represented by `bR mod p`.
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
        // Alias self, _rhs for more readable formulas
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

// impl ConditionallyAssignable for ExtensionFieldElement {
//     fn conditional_assign(&mut self, other: &ExtensionFieldElement, choice: u8) {
//         self.A.conditional_assign(&other.A, choice);
//         self.B.conditional_assign(&other.B, choice);
//     }
// }

impl ConditionallySwappable for ExtensionFieldElement {
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
    // Construct zero.
    pub fn zero() -> ExtensionFieldElement {
        ExtensionFieldElement{
            A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        }
    }
    // Construct one.
    pub fn one() -> ExtensionFieldElement {
        ExtensionFieldElement{
            A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
            B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        }
    }
    // Set output to 1/x.
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

        let mut asq = a * a;                    // = a*a*R*R
        let bsq = b * b;                    // = b*b*R*R
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
    // Set the output to x^2.
    pub fn square(&self) -> ExtensionFieldElement {
        let a = &self.A;
        let b = &self.B;

        // We want to compute
	    //
	    // (a + bi)*(a + bi) = (a^2 - b^2) + 2abi

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
    // Returns true if both sides are equal. Takes variable time.
    pub fn vartime_eq(&self, _rhs: &ExtensionFieldElement) -> bool {
        (&self.A == &_rhs.A) && (&self.B == &_rhs.B)
    }
    // Convert the input to wire format.
    pub fn to_bytes(&self) -> [u8; 188] {
        let mut bytes = [0u8; 188];
        bytes[0..94].clone_from_slice(&self.A.to_bytes());
        bytes[94..188].clone_from_slice(&self.B.to_bytes());
        bytes
    }
    // Read 188 bytes into the given ExtensionFieldElement.
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

// Represents an element of the prime field F_p.
#[derive(Copy, Clone, PartialEq)]
pub struct PrimeFieldElement {
    // This field element is in Montgomery form, so that the value `A` is
	// represented by `aR mod p`.
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
        // Alias self, _rhs for more readable formulas
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

// impl ConditionallyAssignable for PrimeFieldElement {
//     fn conditional_assign(&mut self, other: &PrimeFieldElement, choice: u8) {
//         self.A.conditional_assign(&other.A, choice);
//     }
// }

impl ConditionallySwappable for PrimeFieldElement {
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
    // Construct zero.
    pub fn zero() -> PrimeFieldElement {
        PrimeFieldElement{
            A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        }
    }
    // Construct one.
    pub fn one() -> PrimeFieldElement {
        PrimeFieldElement{
            A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
        }
    }
    // Set the output to x.
    fn set_u64(x: u64) -> PrimeFieldElement {
        let mut output = PrimeFieldElement::zero(); // 0
        output.A.0[0] = x;                          // = x

        let xRR = &output.A * &MONTGOMERY_RSQ;      // = x*R*R
        output.A = xRR.reduce();                    // = x*R mod p
        output
    }
    // Set the output to x^2.
    pub fn square(&self) -> PrimeFieldElement {
        let a = &self.A;      // = a*R
        let b = &self.A;      // = b*R
        let ab = a * b;       // = a*b*R*R
        let _a = ab.reduce(); // = a*b*R mod p

        PrimeFieldElement{ A: _a }
    }
    // Raise self to 2^(2^k)-th power, for k >= 1, by repeated squarings.
    fn pow2k(&self, k: u8) -> PrimeFieldElement {
        let mut result = self.square();
        for _ in 1..k { result = result.square(); }
        result
    }
    // Set output to x^((p-3)/4). If x is square, this is 1/sqrt(x).
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
    // Set output to sqrt(x), if x is a square. If x is nonsquare output is undefined.
    fn sqrt(&self) -> PrimeFieldElement {
        let mut result = self.p34(); // result = (y^2)^((p-3)/4) = y^((p-3)/2)
        result = &result * self;     // result = y^2 * y^((p-3)/2) = y^((p+1)/2)
        // Now result^2 = y^(p+1) = y^2 = x, so result = sqrt(x)
        result
    }
    // Set output to 1/x.
    pub fn inv(&self) -> PrimeFieldElement {
        //let tmp_x = *self;
        let mut result = self.square(); // result = x^2
        result = result.p34();          // result = (x^2)^((p-3)/4) = x^((p-3)/2)
        result = result.square();       // result = x^(p-3)
        result = &result * self;        // result = x^(p-2)
        result
    }
    // Returns true if both sides are equal. Takes variable time.
    pub fn vartime_eq(&self, _rhs: &PrimeFieldElement) -> bool {
        &self.A == &_rhs.A
    }
}

//-----------------------------------------------------------------------------//
//                              Internals                                      //
//-----------------------------------------------------------------------------//

const FP751_NUM_WORDS: usize = 12;

// Internal representation of an element of the base field F_p.
//
// This type is distinct from PrimeFieldElement in that no particular meaning
// is assigned to the representation -- it could represent an element in
// Montgomery form, or not.  Tracking the meaning of the field element is left
// to higher types.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Fp751Element(pub (crate) [u64; FP751_NUM_WORDS]);

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
        unsafe { fpadd751_asm(&self, _rhs, &mut result); }
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
        unsafe { fpsub751_asm(&self, _rhs, &mut result); }
        result
    }
}

impl<'a, 'b> Mul<&'b Fp751Element> for &'a Fp751Element {
    type Output = Fp751X2;
    fn mul(self, _rhs: &'b Fp751Element) -> Fp751X2 {
        let mut result = Fp751X2::zero();
        unsafe { mul751_asm(&self, _rhs, &mut result); } // = a*c*R*R
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

// impl ConditionallyAssignable for Fp751Element {
//     fn conditional_assign(&mut self, other: &Fp751Element, choice: u8) {
//         unsafe { cassign751_asm(self, other, choice); }
//     }
// }

impl ConditionallySwappable for Fp751Element {
    fn conditional_swap(&mut self, other: &mut Fp751Element, choice: u8) {
        unsafe { cswap751_asm(self, other, choice); }
    }
}

impl Eq for Fp751Element {}
impl PartialEq for Fp751Element {
    // This comparison is *not* constant time.
    fn eq(&self, other: &Fp751Element) -> bool {
        let mut _self = *self;
        let mut _other = *other;

        unsafe {
            srdc751_asm(&mut _self);
            srdc751_asm(&mut _other);
        }

        let mut eq: bool = true;
        for i in 0..FP751_NUM_WORDS {
            eq = (_self.0[i] == _other.0[i]) && eq;
        }
        eq
    }
}

impl Equal for Fp751Element {
    fn ct_eq(&self, other: &Fp751Element) -> u8 {
        slices_equal(&self.to_bytes(), &other.to_bytes())
    }
}

impl Debug for Fp751Element {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Fp751Element({:?})", &self.0[..])
    }
}

#[cfg(test)]
impl Arbitrary for Fp751Element {
    fn arbitrary<G: Gen>(g: &mut G) -> Fp751Element {
        g.gen::<Fp751Element>()
    }
}

#[cfg(test)]
impl Rand for Fp751Element {
    fn rand<R: Rng>(rng: &mut R) -> Fp751Element {
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
        let high_limb = rng.next_u64() % 246065832128056;

        Fp751Element([
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            high_limb
        ])
    }
}

impl Fp751Element {
    // Construct a new zero Fp751Element.
    pub fn zero() -> Fp751Element {
        Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    }
    // Reduce a field element in [0, 2*p) to one in [0,p).
    fn strong_reduce(&self) -> Fp751Element {
        let mut _self = *self;
        unsafe { srdc751_asm(&mut _self); }
        _self
    }
    // Given an Fp751Element in Montgomery form, convert to little-endian bytes.
    fn to_bytes(&self) -> [u8; 94] {
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
    // Read an Fp751Element from little-endian bytes and convert to Montgomery form.
    fn from_bytes(bytes: &[u8]) -> Fp751Element {
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

// Represents an intermediate product of two elements of the base field F_p.
#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub struct Fp751X2(pub (crate) [u64; 2*FP751_NUM_WORDS]);

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
        unsafe { mp_add751x2_asm(&self, _rhs, &mut result); }
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
        unsafe { mp_sub751x2_asm(&self, _rhs, &mut result); }
        result
    }
}

impl Debug for Fp751X2 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Fp751X2({:?})", &self.0[..])
    }
}

impl Fp751X2 {
    // Construct a zero Fp751X2.
    fn zero() -> Fp751X2 {
        Fp751X2([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    }
    // Perform Montgomery reduction, x R^{-1} (mod p).
    fn reduce(&self) -> Fp751Element {
        let mut result = Fp751Element::zero();
        unsafe { rdc751_asm(self, &mut result); }
        result
    }
}

// (2^768) mod p
const MONTGOMERY_R : Fp751Element = Fp751Element([149933, 0, 0, 0, 0, 9444048418595930112, 6136068611055053926, 7599709743867700432, 14455912356952952366, 5522737203492907350, 1222606818372667369, 49869481633250]);

// (2^768)^2 mod p
const MONTGOMERY_RSQ : Fp751Element = Fp751Element([2535603850726686808, 15780896088201250090, 6788776303855402382, 17585428585582356230, 5274503137951975249, 2266259624764636289, 11695651972693921304, 13072885652150159301, 4908312795585420432, 6229583484603254826, 488927695601805643, 72213483953973]);

extern {
    // If choice = 1, set x,y = y,x. Otherwise, leave x,y unchanged.
    // This function executes in constant time.
    #[no_mangle]
    pub fn cswap751_asm(x: &mut Fp751Element, y: &mut Fp751Element, choice: u8);
    // If choice = 1, assign y to x. Otherwise, leave x unchanged.
    // This function executes in constant time.
    #[no_mangle]
    pub fn cassign751_asm(x: &mut Fp751Element, y: &Fp751Element, choice: u8);
    // Compute z = x + y (mod p).
    #[no_mangle]
    pub fn fpadd751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element);
    // Compute z = x - y (mod p).
    #[no_mangle]
    pub fn fpsub751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element);
    // Compute z = x * y.
    #[no_mangle]
    pub fn mul751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751X2);
    // Perform Montgomery reduction: set z = x R^{-1} (mod p).
    #[no_mangle]
    pub fn rdc751_asm(x: &Fp751X2, z: &mut Fp751Element);
    // Reduce a field element in [0, 2*p) to one in [0,p).
    #[no_mangle]
    pub fn srdc751_asm(x: &mut Fp751Element);
    // Compute z = x + y, without reducing mod p.
    #[no_mangle]
    pub fn mp_add751_asm(x: &Fp751Element, y: &Fp751Element, z: &mut Fp751Element);
    // Compute z = x + y, without reducing mod p.
    #[no_mangle]
    pub fn mp_add751x2_asm(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2);
    // Compute z = x - y, without reducing mod p.
    #[no_mangle]
    pub fn mp_sub751x2_asm(x: &Fp751X2, y: &Fp751X2, z: &mut Fp751X2);
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
        let one = Fp751Element([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        let two = Fp751Element([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);

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
    //     let mut one = Fp751Element([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    //     let two = Fp751Element([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);

    //     one.conditional_assign(&two, 0);
    //     assert_ne!(one, two);

    //     one.conditional_assign(&two, 1);
    //     assert_eq!(one, two);
    // }
}

//#[cfg(all(test, feature = "bench"))]
#[cfg(test)]
mod bench {
    use super::*;
    use test::Bencher;
    
    static BENCH_X: Fp751Element = Fp751Element([17026702066521327207, 5108203422050077993, 10225396685796065916, 11153620995215874678, 6531160855165088358, 15302925148404145445, 1248821577836769963, 9789766903037985294, 7493111552032041328, 10838999828319306046, 18103257655515297935, 27403304611634]);
    static BENCH_Y: Fp751Element = Fp751Element([4227467157325093378, 10699492810770426363, 13500940151395637365, 12966403950118934952, 16517692605450415877, 13647111148905630666, 14223628886152717087, 7167843152346903316, 15855377759596736571, 4300673881383687338, 6635288001920617779, 30486099554235]);
    static BENCH_Z: Fp751X2 = Fp751X2([1595347748594595712, 10854920567160033970, 16877102267020034574, 12435724995376660096, 3757940912203224231, 8251999420280413600, 3648859773438820227, 17622716832674727914, 11029567000887241528, 11216190007549447055, 17606662790980286987, 4720707159513626555, 12887743598335030915, 14954645239176589309, 14178817688915225254, 1191346797768989683, 12629157932334713723, 6348851952904485603, 16444232588597434895, 7809979927681678066, 14642637672942531613, 3092657597757640067, 10160361564485285723, 240071237]);
    static mut BENCH_FP751ELEMENT: Fp751Element = Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);
    static mut BENCH_FP751X2: Fp751X2 = Fp751X2([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);

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
        b.iter(|| unsafe { mul751_asm(&BENCH_X, &BENCH_Y, &mut BENCH_FP751X2) });
    }

    #[bench]
    fn fp751_rdc(b: &mut Bencher) {
        b.iter(|| unsafe { rdc751_asm(&BENCH_Z, &mut BENCH_FP751ELEMENT) });
    }

    #[bench]
    fn fp751_add(b: &mut Bencher) {
        b.iter(|| unsafe { fpadd751_asm(&BENCH_X, &BENCH_Y, &mut BENCH_FP751ELEMENT) });
    }

    #[bench]
    fn fp751_sub(b: &mut Bencher) {
        b.iter(|| unsafe { fpsub751_asm(&BENCH_X, &BENCH_Y, &mut BENCH_FP751ELEMENT) });
    }
}
