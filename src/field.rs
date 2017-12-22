use core::fmt::Debug;

//-----------------------------------------------------------------------------//
//                           Extension Field                                   //
//-----------------------------------------------------------------------------//

// Represents an element of the extension field F_{p^2}.
struct ExtensionFieldElement {
    // This field element is in Montgomery form, so that the value `A` is
    // represented by `aR mod p`.
    A: Fp751Element,
    // This field element is in Montgomery form, so that the value `B` is
    // represented by `bR mod p`.
    B: Fp751Element,
}

impl ExtensionFieldElement {
    /// Construct zero.
    fn zero() -> ExtensionFieldElement {
        ExtensionFieldElement {
            A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
            B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        }
    }
    /// Construct one.
    fn one() -> ExtensionFieldElement {
         ExtensionFieldElement {
            A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
            B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        }
    }
}

//-----------------------------------------------------------------------------//
//                             Prime Field                                     //
//-----------------------------------------------------------------------------//

pub struct PrimeFieldElement {
    pub A: Fp751Element,
}

impl PrimeFieldElement {
    /// Construct zero.
    fn zero() -> PrimeFieldElement {
        PrimeFieldElement {
            A: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        }
    }

    /// Construct one.
    fn one() -> PrimeFieldElement {
        PrimeFieldElement {
            A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
        }
    }
}

//-----------------------------------------------------------------------------//
//                              Internals                                      //
//-----------------------------------------------------------------------------//

const FP751_NUM_WORDS : usize = 12;

// Internal representation of an element of the base field F_p.
//
// This type is distinct from PrimeFieldElement in that no particular meaning
// is assigned to the representation -- it could represent an element in
// Montgomery form, or not.  Tracking the meaning of the field element is left
// to higher types.
#[derive(Copy, Clone, PartialEq)]
pub struct Fp751Element(pub (crate) [u64; FP751_NUM_WORDS]);

impl Debug for Fp751Element {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Fp751Element({:?})", &self.0[..])
    }
}

// Represents an intermediate product of two elements of the base field F_p.
#[derive(PartialEq)]
pub struct Fp751X2(pub (crate) [u64; 2*FP751_NUM_WORDS]);

impl Debug for Fp751X2 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Fp751X2Element({:?})", &self.0[..])
    }
}

// (2^768) mod p
const MONTGOMERY_R : Fp751Element = Fp751Element([149933, 0, 0, 0, 0, 9444048418595930112, 6136068611055053926, 7599709743867700432, 14455912356952952366, 5522737203492907350, 1222606818372667369, 49869481633250]);

// (2^768)^2 mod p
const MONTGOMERY_RSQ : Fp751Element = Fp751Element([2535603850726686808, 15780896088201250090, 6788776303855402382, 17585428585582356230, 5274503137951975249, 2266259624764636289, 11695651972693921304, 13072885652150159301, 4908312795585420432, 6229583484603254826, 488927695601805643, 72213483953973]);

extern {
    // If choice = 0, leave x,y unchanged. If choice = 1, set x,y = y,x.
    // This function executes in constant time.
    pub fn cswap751_asm(x: &Fp751Element, y: &Fp751Element, choice: u8);
    // If choice = 0, set z = x. If choice = 1, set z = y.
    // This function executes in constant time.
    //
    // Can overlap z with x or y or both.
    pub fn cassign751_asm(x: &Fp751Element, y: &Fp751Element, z: &Fp751Element, choice: u8);
    // Compute z = x + y (mod p).
    pub fn fpadd751_asm(x: &Fp751Element, y: &Fp751Element, z: &Fp751Element);
    // Compute z = x - y (mod p).
    pub fn fpsub751_asm(x: &Fp751Element, y: &Fp751Element, z: &Fp751Element);
    // Compute z = x * y.
    pub fn mul751_asm(x: &Fp751Element, y: &Fp751Element, z: &Fp751X2);
    // Perform Montgomery reduction: set z = x R^{-1} (mod p).
    // Destroys the input value.
    pub fn rdc751_asm(x: &Fp751X2, z: &Fp751Element);
    // Reduce a field element in [0, 2*p) to one in [0,p).
    pub fn srdc751_asm(x: &Fp751Element);
    // Compute z = x + y, without reducing mod p.
    pub fn mp_add751_asm(x: &Fp751Element, y: &Fp751Element, z: &Fp751Element);
    // Compute z = x + y, without reducing mod p.
    pub fn mp_add751x2_asm(x: &Fp751X2, y: &Fp751X2, z: &Fp751X2);
    // Compute z = x - y, without reducing mod p.
    pub fn mp_sub751x2_asm(x: &Fp751X2, y: &Fp751X2, z: &Fp751X2);
}
