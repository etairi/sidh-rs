use ::field::{Fp751Element, PrimeFieldElement, ExtensionFieldElement};
use ::constants::*;

use core::fmt::Debug;
use subtle::ConditionallySwappable;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen, QuickCheck};

// Macro to assign tuples, as Rust does not allow tuples as lvalue.
macro_rules! assign{
    {($v1:ident, $v2:ident) = $e:expr} =>
    {
        {
            let (v1, v2) = $e;
            $v1 = v1;
            $v2 = v2;
        }
    };
}

// = 256
const CONST_256: ExtensionFieldElement = ExtensionFieldElement {
    A: Fp751Element([0x249ad67, 0x0, 0x0, 0x0, 0x0, 0x730000000000000, 0x738154969973da8b, 0x856657c146718c7f, 0x461860e4e363a697, 0xf9fd6510bba838cd, 0x4e1a3c3f06993c0c, 0x55abef5b75c7]),
    B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
};

// A point on the projective line P^1(F_{p^2}).
//
// This is used to work projectively with the curve coefficients.
#[derive(Copy, Clone, PartialEq)]
pub struct ProjectiveCurveParameters {
    pub A: ExtensionFieldElement,
    pub C: ExtensionFieldElement,
}

struct CachedCurveParameters {
    Aplus2C: ExtensionFieldElement,
    C4: ExtensionFieldElement,
}

struct CachedTripleCurveParameters {
    Aminus2C: ExtensionFieldElement,
    C2: ExtensionFieldElement,
}

impl Debug for ProjectiveCurveParameters {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "ProjectiveCurveParameters(A: {:?}\nC: {:?})", &self.A, &self.C)
    }
}

#[cfg(test)]
impl Arbitrary for ProjectiveCurveParameters {
    fn arbitrary<G: Gen>(g: &mut G) -> ProjectiveCurveParameters {
        let a = g.gen::<ExtensionFieldElement>();
        let c = g.gen::<ExtensionFieldElement>();
        ProjectiveCurveParameters { A: a, C: c }
    }
}

impl ProjectiveCurveParameters {
    pub fn from_affine(a: &ExtensionFieldElement) -> ProjectiveCurveParameters {
        ProjectiveCurveParameters {
            A: *a,
            C: ExtensionFieldElement::one()
        }
    }
    // Recover the curve parameters from three points on the curve.
    pub fn recover_curve_parameters(affine_xP: &ExtensionFieldElement, affine_xQ: &ExtensionFieldElement, affine_xQmP: &ExtensionFieldElement) -> 
                                ProjectiveCurveParameters 
    {
        let mut t0 = ExtensionFieldElement::one(); // = 1
        let mut t1 = affine_xP * affine_xQ;        // = x_P * x_Q
        t0 = &t0 - &t1;                            // = 1 - x_P * x_Q
        t1 = affine_xP * affine_xQmP;              // = x_P * x_{Q-P}
        t0 = &t0 - &t1;                            // = 1 - x_P * x_Q - x_P * x_{Q-P}
        t1 = affine_xQ * affine_xQmP;              // = x_Q * x_{Q-P}
        t0 = &t0 - &t1;                            // = 1 - x_P * x_Q - x_P * x_{Q-P} - x_Q * x_{Q-P}
        let mut a = t0.square();                   // = (1 - x_P * x_Q - x_P * x_{Q-P} - x_Q * x_{Q-P})^2
        t1 = &t1 * affine_xP;                      // = x_P * x_Q * x_{Q-P}
        t1 = &t1 + &t1;                            // = 2 * x_P * x_Q * x_{Q-P}
        let c = &t1 + &t1;                         // = 4 * x_P * x_Q * x_{Q-P}
        t0 = affine_xP + affine_xQ;                // = x_P + x_Q
        t0 = &t0 + affine_xQmP;                    // = x_P + x_Q + x_{Q-P}
        t1 = &c * &t0;                             // = 4 * x_P * x_Q * x_{Q-P} * (x_P + x_Q + x_{Q-P})
        a = &a - &t1;                              // = (1 - x_P * x_Q - x_P * x_{Q-P} - x_Q * x_{Q-P})^2 - 4 * x_P * x_Q * x_{Q-P} * (x_P + x_Q + x_{Q-P})
        
        ProjectiveCurveParameters{ A: a, C: c }
    }
    // Compute the j-invariant (not the J-invariant) of the given curve.
    pub fn j_invariant(&self) -> ExtensionFieldElement {
        let a = &self.A;
        let c = &self.C;
        let mut v0 = c.square();    // C^2
        let mut v1 = a.square();    // A^2
        let mut v2 = &v0 + &v0;     // 2C^2
        let mut v3 = &v2 + &v0;     // 3C^2
        v2 = &v2 + &v2;             // 4C^2
        v2 = &v1 - &v2;             // A^2 - 4C^2
        v1 = &v1 - &v3;             // A^2 - 3C^2
        v3 = v1.square();           // (A^2 - 3C^2)^2
        v3 = &v3 * &v1;             // (A^2 - 3C^2)^3
        v0 = v0.square();           // C^4
        v3 = &v3 * &CONST_256;      // 256(A^2 - 3C^2)^3
        v2 = &v2 * &v0;             // C^4(A^2 - 4C^2)
        v2 = v2.inv();              // 1/C^4(A^2 - 4C^2)
        v0 = &v3 * &v2;             // 256(A^2 - 3C^2)^3 / C^4(A^2 - 4C^2)

        v0
    }
    // Compute cached parameters A + 2C, 4C.
    fn cached_params(&self) -> CachedCurveParameters {
        let mut Aplus2C = &self.C + &self.C; // = 2*C
        let C4 = &Aplus2C + &Aplus2C;        // = 4*C
        Aplus2C = &Aplus2C + &self.A;        // = 2*C + A

        CachedCurveParameters{ Aplus2C, C4 }
    }
    // Compute cached parameters A - 2C, 2C.
    fn cached_triple_params(&self) -> CachedTripleCurveParameters {
        let C2 = &self.C + &self.C;   // = 2*C
        let Aminus2C = &self.A - &C2; // = A -2*C

        CachedTripleCurveParameters{ Aminus2C, C2 }
    }
}

// A point on the projective line P^1(F_{p^2}).
//
// This represents a point on the (Kummer line) of a Montgomery curve.  The
// curve is specified by a ProjectiveCurveParameters struct.
#[derive(Copy, Clone, PartialEq)]
pub struct ProjectivePoint {
    pub X: ExtensionFieldElement,
    pub Z: ExtensionFieldElement,
}

impl ConditionallySwappable for ProjectivePoint {
    fn conditional_swap(&mut self, other: &mut ProjectivePoint, choice: u8) {
        (&mut self.X).conditional_swap(&mut other.X, choice);
        (&mut self.Z).conditional_swap(&mut other.Z, choice);
    }
}

impl Debug for ProjectivePoint {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "ProjectivePoint(X: {:?}\nZ: {:?})", &self.X, &self.Z)
    }
}

#[cfg(test)]
impl Arbitrary for ProjectivePoint {
    fn arbitrary<G: Gen>(g: &mut G) -> ProjectivePoint {
        let x = g.gen::<ExtensionFieldElement>();
        let z = g.gen::<ExtensionFieldElement>();
        ProjectivePoint{ X: x, Z: z }
    }
}

impl ProjectivePoint {
    // Creates a new empty ProejctivePoint.
    pub fn new() -> ProjectivePoint {
        ProjectivePoint{ X: ExtensionFieldElement::zero(), Z: ExtensionFieldElement::zero() }
    }

    pub fn from_affine_prime_field(x: &PrimeFieldElement) -> ProjectivePoint {
        let _X = ExtensionFieldElement{ A: x.A, B: ExtensionFieldElement::zero().B };
        ProjectivePoint{
            X: _X,
            Z: ExtensionFieldElement::one()
        }
    }

    pub fn from_affine(x: &ExtensionFieldElement) -> ProjectivePoint {
        ProjectivePoint{
            X: *x,
            Z: ExtensionFieldElement::one()
        }
    }

    pub fn to_affine(&self) -> ExtensionFieldElement {
        let affine_x = &self.Z.inv() * &self.X;
        affine_x
    }
    // Returns true if both sides are equal. Takes variable time.
    pub fn vartime_eq(&self, _rhs: &ProjectivePoint) -> bool {
        let t0 = &self.X * &_rhs.Z;
        let t1 = &self.Z * &_rhs.X;
        t0.vartime_eq(&t1)
    }
    // Given xP = x(P), xQ = x(Q), and xPmQ = x(P-Q), compute xR = x(P+Q).
    fn add(&self, xQ: &ProjectivePoint, xPmQ: &ProjectivePoint) -> ProjectivePoint {
        let xP = *self;
        // Algorithm 1 of Costello-Smith.
        let mut v0 = &xP.X + &xP.Z;         // X_P + Z_P
        let v1 = &(&xQ.X - &xQ.Z) * &v0;    // (X_Q - Z_Q)(X_P + Z_P)
        v0 = &xP.X - &xP.Z;                 // X_P - Z_P
        let v2 = &(&xQ.X + &xQ.Z) * &v0;    // (X_Q + Z_Q)(X_P - Z_P)
        let v3 = (&v1 + &v2).square();      // 4(X_Q X_P - Z_Q Z_P)^2
        let v4 = (&v1 - &v2).square();      // 4(X_Q Z_P - Z_Q X_P)^2
        v0 = &xPmQ.Z * &v3;                 // 4X_{P-Q}(X_Q X_P - Z_Q Z_P)^2
        let z = &xPmQ.X * &v4;              // 4Z_{P-Q}(X_Q Z_P - Z_Q X_P)^2
        let x = v0;

        ProjectivePoint{ X: x, Z: z }
    }
    // Given xP = x(P) and cached curve parameters Aplus2C = A + 2*C, C4 = 4*C, compute xQ = x([2]P).
    fn double(&self, curve: &CachedCurveParameters) -> ProjectivePoint {
        let xP = *self;
        // Algorithm 2 of Costello-Smith, amended to work with projective curve coefficients.
        let v1 = (&xP.X + &xP.Z).square();      // (X+Z)^2
        let mut v2 = (&xP.X - &xP.Z).square();  // (X-Z)^2
        let xz4 = &v1 - &v2;                    // 4XZ = (X+Z)^2 - (X-Z)^2
        v2 = &v2 * &curve.C4;                   // 4C(X-Z)^2
        let x = &v1 * &v2;                      // 4C(X+Z)^2(X-Z)^2
        let mut v3 = &xz4 * &curve.Aplus2C;     // 4XZ(A + 2C)
        v3 = &v3 + &v2;                         // 4XZ(A + 2C) + 4C(X-Z)^2
        let z = &v3 * &xz4;                     // (4XZ(A + 2C) + 4C(X-Z)^2)4XZ
        // Now (xQ.x : xQ.z)
        //   = (4C(X+Z)^2(X-Z)^2 : (4XZ(A + 2C) + 4C(X-Z)^2)4XZ )
        //   = ((X+Z)^2(X-Z)^2 : (4XZ((A + 2C)/4C) + (X-Z)^2)4XZ )
        //   = ((X+Z)^2(X-Z)^2 : (4XZ((a + 2)/4) + (X-Z)^2)4XZ )
        ProjectivePoint{ X: x, Z: z }
    }
    // dbl_add method calculates the x-coordinate of 2P and P+Q from the x-coordinate of P, Q and P-Q.
    // Params: C4 = 4*C and Aplus2C = (A+2C)
    // Cost: 8M+4S+8A in Fp2
    fn dbl_add(&self, xQ: &ProjectivePoint, xPmQ: &ProjectivePoint, params: &CachedCurveParameters) ->
              (ProjectivePoint, ProjectivePoint)
    {
        let xP = *self;
        let (x1, z1) = (&xPmQ.X, &xPmQ.Z);
        let (x2, z2) = (&xP.X, &xP.Z);
        let (x3, z3) = (&xQ.X, &xQ.Z);

        let mut t0 = x2 + z2;   // A = x2+z2
        let mut t1 = x2 - z2;   // B = x2-z2
        let mut t3 = x3 + z3;   // C = x3+z3
        let mut t2 = x3 - z3;   // D = x3-z3
        t2 = &t2 * &t0;         // DA = D*A
        t3 = &t3 * &t1;         // CB = C*B

        let mut x = &t2 + &t3;  // x5 = DA+CB
        let mut z = &t2 - &t3;  // z5 = DA-CB
        x = x.square();         // x5 = (DA+CB)^2
        z = z.square();         // z5 = (DA-CB)^2
        x = &x * z1;            // x5 = z1*(DA+CB)^2
        z = &z * x1;            // z5 = x1*(DA-CB)^2
        let xPaddQ = ProjectivePoint { X: x, Z: z };

        t0 = t0.square();           // t0 = AA = A^2
        t1 = t1.square();           // t1 = BB = B^2
        t2 = &t0 - &t1;             // t2 = E = AA-BB
        t3 = &t1 * &params.C4;      // t3 = (4C)*BB
        z = &t2 * &params.Aplus2C;  // z4 = (A+2C)*E
        z = &z + &t3;               // z4 = (4C)*BB+(A+2C)*E
        x = &t0 * &t3;              // x4 = AA*(4C)*BB
        z = &z * &t2;               // z4 = E*((4C)*BB+(A+2C)*E)
        let x2P = ProjectivePoint{ X: x, Z: z };

        (x2P, xPaddQ)
    }
    // Given the curve parameters, xP = x(P), and k >= 0, compute xQ = x([2^k]P).
    pub fn pow2k(&self, curve: &ProjectiveCurveParameters, k: u32) -> ProjectivePoint {
        let cached_params = curve.cached_params();
        let mut xQ = *self;
        for _ in 0..k { xQ = xQ.double(&cached_params); }
        xQ
    }
    // Uses the efficient Montgomery tripling formulas from FLOR-SIDH-x64
    // Given xP = x(P) and cached tripling curve parameters Aminus2C = A - 2*C, C2 = 2*C, compute xQ = x([3]P).
    // Returns xQ to allow chaining.  Safe to overlap xP, xQ.
    // Reference: A faster SW implementation of SIDH (github.com/armfazh/flor-sidh-x64).
    fn triple(&self, curve: &CachedTripleCurveParameters) -> ProjectivePoint {
        let xP = *self;
        let (x1, z1) = (&xP.X, &xP.Z);
        let mut t0 = x1.square();           // t0 = x1^2
        let mut t1 = z1.square();           // t1 = z1^2
        let mut t2 = x1 + z1;               // t2 = x1+z1
        t2 = t2.square();                   // t2 = t2^2
        let t3 = &t0 + &t1;                 // t3 = t0+t1
        let mut t4 = &t2 - &t3;             // t4 = t2-t3
        let mut t5 = &curve.Aminus2C * &t4; // t5 = (A-2C)*t4
        t2 = &curve.C2 * &t2;               // t2 = (2C)*t2
        t5 = &t5 + &t2;                     // t5 = t2+t5
        t5 = &t5 + &t5;                     // t5 = t5+t5
        t5 = &t5 + &t5;                     // t5 = t5+t5
        t0 = &t0 * &t5;                     // t0 = t0*t5
        t1 = &t1 * &t5;                     // t1 = t1*t5
        t4 = &t3 - &t4;                     // t4 = t3-t4
        t2 = &t2 * &t4;                     // t2 = t2*t4
        t0 = &t2 - &t0;                     // t0 = t2-t0
        t1 = &t2 - &t1;                     // t1 = t2-t1
        t0 = t0.square();                   // t0 = t0^2
        t1 = t1.square();                   // t1 = t1^2
        let x = x1 * &t1;                   // x3 = x1*t1
        let z = z1 * &t0;                   // z3 = z1*t0

        ProjectivePoint{ X: x, Z: z }
    }
    // Given the curve parameters, xP = x(P), and k >= 0, compute xQ = x([3^k]P).
    pub fn pow3k(&self, curve: &ProjectiveCurveParameters, k: u32) -> ProjectivePoint {
        let cached_params = curve.cached_triple_params();
        let mut xQ = *self;
        for _ in 0..k { xQ = xQ.triple(&cached_params); }
        xQ
    }
    // Given x(P) and a scalar m in little-endian bytes, compute x([m]P) using the
    // Montgomery ladder. This is described in Algorithm 8 of Costello-Smith.
    //
    // This function's execution time is dependent only on the byte-length of the
    // input scalar. All scalars of the same input length execute in uniform time.
    // The scalar can be padded with zero bytes to ensure a uniform length.
    fn scalar_mul(&self, curve: &ProjectiveCurveParameters, scalar: &[u8]) -> ProjectivePoint {
        let xP = *self;
        let cached_params = curve.cached_params();
        let mut x0 = ProjectivePoint{ X: ExtensionFieldElement::one(), Z: ExtensionFieldElement::zero() };
        let mut x1 = xP;
        let mut tmp: ProjectivePoint;

        // Iterate over the bits of the scalar, top to bottom.
        let mut prev_bit: u8 = 0;
        for i in (0..scalar.len()).rev() {
            let scalar_byte = scalar[i];
            for j in (0..8).rev() {
                let bit = (scalar_byte >> (j as u32)) & 0x1;
                (&mut x0).conditional_swap(&mut x1, (bit ^ prev_bit));
                tmp = x0.double(&cached_params);
                x1 = x0.add(&x1, &xP);
                x0 = tmp;
                prev_bit = bit;
            }
        }
        // Now prev_bit is the lowest bit of the scalar.
        (&mut x0).conditional_swap(&mut x1, prev_bit);
        let xQ = x0;
        xQ
    }
    // Given P = (x_P, y_P) in affine coordinates, as well as projective points
    // x(Q), x(R) = x(P+Q), all in the prime-field subgroup of the starting curve
    // E_0(F_p), use the Okeya-Sakurai coordinate recovery strategy to recover Q =
    // (X_Q : Y_Q : Z_Q).
    //
    // This is Algorithm 5 of Costello-Smith, with the constants a = 0, b = 1 hardcoded.
    fn okeya_sakurai_coordinate_recovery(affine_xP: &PrimeFieldElement, affine_yP: &PrimeFieldElement,
                                         xQ: &ProjectivePrimeFieldPoint, xR: &ProjectivePrimeFieldPoint) ->
                                        (PrimeFieldElement, PrimeFieldElement, PrimeFieldElement)
    {
        let mut v1 = affine_xP * &xQ.Z;      // = x_P*Z_Q
        let mut v2 = &xQ.X + &v1;            // = X_Q + x_P*Z_Q
        let mut v3 = (&xQ.X - &v1).square(); // = (X_Q - x_P*Z_Q)^2
        v3 = &v3 * &xR.X;                    // = X_R*(X_Q - x_P*Z_Q)^2
        // Skip setting v1 = 2a*Z_Q (step 6) since we hardcode a = 0.
	    // Skip adding v1 to v2 (step 7) since v1 is zero.
        let mut v4 = affine_xP * &xQ.X; // = x_P*X_Q
        v4 = &v4 + &xQ.Z;               // = x_P*X_Q + Z_Q
        v2 = &v2 * &v4;                 // = (x_P*X_Q + Z_Q)*(X_Q + x_P*Z_Q)
        // Skip multiplication by v1 (step 11) since v1 is zero.
	    // Skip subtracting v1 from v2 (step 12) since v1 is zero.
        v2 = &v2 * &xR.Z;               // = (x_P*X_Q + Z_Q)*(X_Q + x_P*Z_Q)*Z_R
        let Y_Q = &v2 - &v3;            // = (x_P*X_Q + Z_Q)*(X_Q + x_P*Z_Q)*Z_R - X_R*(X_Q - x_P*Z_Q)^2
        v1 = affine_yP + affine_yP;     // = 2b*y_P
        v1 = &(&v1 * &xQ.Z) * &xR.Z;    // = 2b*y_P*Z_Q*Z_R
        let X_Q = &v1 * &xQ.X;          // = 2b*y_P*Z_Q*Z_R*X_Q
        let Z_Q = &v1 * &xQ.Z;          // = 2b*y_P*Z_Q^2*Z_R

        (X_Q, Y_Q, Z_Q)
    }
    // Given x(P), x(Q), x(P-Q), as well as a scalar m in little-endian bytes,
    // compute x(P + [m]Q) using the "three-point ladder" of de Feo, Jao, and Plut.
    //
    // Safe to overlap the source with the destination.
    //
    // This function's execution time is dependent only on the byte-length of the
    // input scalar.  All scalars of the same input length execute in uniform time.
    // The scalar can be padded with zero bytes to ensure a uniform length.
    //
    // The algorithm, as described in de Feo-Jao-Plut, is as follows:
    //
    // (x0, x1, x2) <--- (x(O), x(Q), x(P))
    //
    // for i = |m| down to 0, indexing the bits of m:
    //     Invariant: (x0, x1, x2) == (x( [t]Q ), x( [t+1]Q ), x( P + [t]Q ))
    //          where t = m//2^i is the high bits of m, starting at i
    //     if m_i == 0:
    //         (x0, x1, x2) <--- (xDBL(x0), xADD(x1, x0, x(Q)), xADD(x2, x0, x(P)))
    //         Invariant: (x0, x1, x2) == (x( [2t]Q ), x( [2t+1]Q ), x( P + [2t]Q ))
    //                                 == (x( [t']Q ), x( [t'+1]Q ), x( P + [t']Q ))
    //              where t' = m//2^{i-1} is the high bits of m, starting at i-1
    //     if m_i == 1:
    //         (x0, x1, x2) <--- (xADD(x1, x0, x(Q)), xDBL(x1), xADD(x2, x1, x(P-Q)))
    //         Invariant: (x0, x1, x2) == (x( [2t+1]Q ), x( [2t+2]Q ), x( P + [2t+1]Q ))
    //                                 == (x( [t']Q ),   x( [t'+1]Q ), x( P + [t']Q ))
    //              where t' = m//2^{i-1} is the high bits of m, starting at i-1
    // return x2
    //
    // Notice that the roles of (x0,x1) and (x(P), x(P-Q)) swap depending on the
    // current bit of the scalar.  Instead of swapping which operations we do, we
    // can swap variable names, producing the following uniform algorithm:
    //
    // (x0, x1, x2) <--- (x(O), x(Q), x(P))
    // (y0, y1) <--- (x(P), x(P-Q))
    //
    // for i = |m| down to 0, indexing the bits of m:
    //      (x0, x1) <--- SWAP( m_{i+1} xor m_i, (x0,x1) )
    //      (y0, y1) <--- SWAP( m_{i+1} xor m_i, (y0,y1) )
    //      (x0, x1, x2) <--- ( xDBL(x0), xADD(x1,x0,x(Q)), xADD(x2, x0, y0) )
    //
    // return x2
    //
    pub fn three_point_ladder(xP: &ProjectivePoint, xQ: &ProjectivePoint, xPmQ: &ProjectivePoint, 
                              curve: &ProjectiveCurveParameters, scalar: &[u8]) -> ProjectivePoint
    {
        let cached_params = curve.cached_params();

        // (x0, x1, x2) <--- (x(O), x(Q), x(P))
        let mut x0 = ProjectivePoint{ X: ExtensionFieldElement::one(), Z: ExtensionFieldElement::zero() };
        let mut x1 = *xQ;
        let mut x2 = *xP;
        // (y0, y1) <--- (x(P), x(P-Q))
        let mut y0 = *xP;
        let mut y1 = *xPmQ;

        // Iterate over the bits of the scalar, top to bottom.
        let mut prev_bit: u8 = 0;
        for i in (0..scalar.len()).rev() {
            let scalar_byte = scalar[i];
            for j in (0..8).rev() {
                let bit = (scalar_byte >> (j as u32)) & 0x1;
                (&mut x0).conditional_swap(&mut x1, (bit ^ prev_bit));
                (&mut y0).conditional_swap(&mut y1, (bit ^ prev_bit));
                x1 = x1.add(&x0, xQ); // = xADD(x1, x0, x(Q))
                assign!{(x0, x2) = x0.dbl_add(&x2, &y0, &cached_params)};
                prev_bit = bit;
            }
        }

        let xR = x2;
        xR
    }
    // Right-to-left point multiplication, which given the x-coordinate
    // of P, Q and P-Q calculates the x-coordinate of R=P+[k]Q.
    pub fn right_to_left_ladder(xP: &ProjectivePoint, xQ: &ProjectivePoint, xPmQ: &ProjectivePoint,
                                curve: &ProjectiveCurveParameters, scalar: &[u8]) -> ProjectivePoint
    {
        let cached_params = curve.cached_params();
        let mut R1 = *xP;
        let mut R2 = *xPmQ;
        let mut R0 = *xQ;

        // Iterate over the bits of the scalar, bottom to top.
        let mut prev_bit: u8 = 0;
        for i in 0..scalar.len() {
            let scalar_byte = scalar[i];
            for j in 0..8 {
                let bit = (scalar_byte >> (j as u32)) & 0x1;
                (&mut R1).conditional_swap(&mut R2, (bit ^ prev_bit));
                assign!{(R0, R2) = R0.dbl_add(&R2, &R1, &cached_params)};
                prev_bit = bit;
            }
        }
        (&mut R1).conditional_swap(&mut R2, prev_bit);
        let xR = R1;
        xR
    }
    // Given the affine x-coordinate affine_xP of P, compute the x-coordinate
    // x(\tau(P)-P) of \tau(P)-P.
    pub fn distort_and_difference(affine_xP: &PrimeFieldElement) -> ProjectivePoint {
        let mut t0 = affine_xP.square();            // = x_P^2
        let t1 = &PrimeFieldElement::one() + &t0;   // = x_P^2 + 1
        let b = t1.A;                               // = 0 + (x_P^2 + 1)*i
        t0 = affine_xP + affine_xP;                 // = 2*x_P
        let a = t0.A;                               // = 2*x_P + 0*i

        let x = ExtensionFieldElement { A: Fp751Element::zero(), B: b };
        let z = ExtensionFieldElement { A: a, B: Fp751Element::zero() };
        let xR = ProjectivePoint { X: x, Z: z };
        xR
    }
    // Given an affine point P = (x_P, y_P) in the prime-field subgroup of the
    // starting curve E_0(F_p), together with a secret scalar m, compute x(P+[m]Q),
    // where Q = \tau(P) is the image of P under the distortion map described
    // below.
    //
    // The computation uses basically the same strategy as the
    // Costello-Longa-Naehrig implementation:
    //
    // 1. Use the standard Montgomery ladder to compute x([m]Q), x([m+1]Q)
    //
    // 2. Use Okeya-Sakurai coordinate recovery to recover [m]Q from Q, x([m]Q),
    // x([m+1]Q)
    //
    // 3. Use P and [m]Q to compute x(P + [m]Q)
    //
    // The distortion map \tau is defined as
    //
    // \tau : E_0(F_{p^2}) ---> E_0(F_{p^2})
    //
    // \tau : (x,y) |---> (-x, iy).
    //
    // The image of the distortion map is the _trace-zero_ subgroup of E_0(F_{p^2})
    // defined by Tr(P) = P + \pi_p(P) = id, where \pi_p((x,y)) = (x^p, y^p) is the
    // p-power Frobenius map.  To see this, take P = (x,y) \in E_0(F_{p^2}).  Then
    // Tr(P) = id if and only if \pi_p(P) = -P, so that
    //
    // -P = (x, -y) = (x^p, y^p) = \pi_p(P);
    //
    // we have x^p = x if and only if x \in F_p, while y^p = -y if and only if y =
    // i*y' for y' \in F_p.
    //
    // Thus (excepting the identity) every point in the trace-zero subgroup is of
    // the form \tau((x,y)) = (-x,i*y) for (x,y) \in E_0(F_p).
    //
    // Since the Montgomery ladder only uses the x-coordinate, and the x-coordinate
    // is always in the prime subfield, we can compute x([m]Q), x([m+1]Q) entirely
    // in the prime subfield.
    //
    // The affine form of the relation for Okeya-Sakurai coordinate recovery is
    // given on p. 13 of Costello-Smith:
    //
    // y_Q = ((x_P*x_Q + 1)*(x_P + x_Q + 2*a) - 2*a - x_R*(x_P - x_Q)^2)/(2*b*y_P),
    //
    // where R = Q + P and a,b are the Montgomery parameters.  In our setting
    // (a,b)=(0,1) and our points are P=Q, Q=[m]Q, P+Q=[m+1]Q, so this becomes
    //
    // y_{mQ} = ((x_Q*x_{mQ} + 1)*(x_Q + x_{mQ}) - x_{m1Q}*(x_Q - x_{mQ})^2)/(2*y_Q)
    //
    // y_{mQ} = ((1 - x_P*x_{mQ})*(x_{mQ} - x_P) - x_{m1Q}*(x_P + x_{mQ})^2)/(2*y_P*i)
    //
    // y_{mQ} = i*((1 - x_P*x_{mQ})*(x_{mQ} - x_P) - x_{m1Q}*(x_P + x_{mQ})^2)/(-2*y_P)
    //
    // since (x_Q, y_Q) = (-x_P, y_P*i).  In projective coordinates this is
    //
    // Y_{mQ}' = ((Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})*Z_{m1Q}
    //          - X_{m1Q}*(X_{mQ} + x_P*Z_{mQ})^2)
    //
    // with denominator
    //
    // Z_{mQ}' = (-2*y_P*Z_{mQ}*Z_{m1Q})*Z_{mQ}.
    //
    // Setting
    //
    // X_{mQ}' = (-2*y_P*Z_{mQ}*Z_{m1Q})*X_{mQ}
    //
    // gives [m]Q = (X_{mQ}' : i*Y_{mQ}' : Z_{mQ}') with X,Y,Z all in F_p.  (Here
    // the ' just denotes that we've added extra terms to the denominators during
    // the computation of Y)
    //
    // To compute the x-coordinate x(P+[m]Q) from P and [m]Q, we use the affine
    // addition formulas of section 2.2 of Costello-Smith.  We're only interested
    // in the x-coordinate, giving
    //
    // X_R = Z_{mQ}*(i*Y_{mQ} - y_P*Z_{mQ})^2 - (x_P*Z_{mQ} + X_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2
    //
    // Z_R = Z_{mQ}*(X_{mQ} - x_P*Z_{mQ})^2.
    //
    // Notice that although X_R \in F_{p^2}, we can split the computation into
    // coordinates X_R = X_{R,a} + X_{R,b}*i as
    //
    // (i*Y_{mQ} - y_P*Z_{mQ})^2 = (y_P*Z_{mQ})^2 - Y_{mQ}^2 - 2*y_P*Z_{mQ}*Y_{mQ}*i,
    //
    // giving
    //
    // X_{R,a} = Z_{mQ}*((y_P*Z_{mQ})^2 - Y_{mQ}^2)
    //         - (x_P*Z_{mQ} + X_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2
    //
    // X_{R,b} = -2*y_P*Y_{mQ}*Z_{mQ}^2
    //
    // Z_R = Z_{mQ}*(X_{mQ} - x_P*Z_{mQ})^2.
    //
    // These formulas could probably be combined with the formulas for y-recover
    // and computed more efficiently, but efficiency isn't the biggest concern
    // here, since the bulk of the cost is already in the ladder.
    pub fn secret_point(affine_xP: &PrimeFieldElement, affine_yP: &PrimeFieldElement, scalar: &[u8]) -> ProjectivePoint {
        let mut xQ = ProjectivePrimeFieldPoint::from_affine(affine_xP);
        xQ.X = -(&xQ.X);

        // Compute x([m]Q) = (X_{mQ} : Z_{mQ}), x([m+1]Q) = (X_{m1Q} : Z_{m1Q}).
        let (xmQ, xm1Q) = ProjectivePrimeFieldPoint::scalar_mul_prime_field(&xQ, &E0_A_PLUS2_OVER4, scalar);

        // Now perform coordinate recovery:
	    // [m]Q = (X_{mQ} : Y_{mQ}*i : Z_{mQ})

        // Y_{mQ} = (Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})*Z_{m1Q}
	    //          - X_{m1Q}*(X_{mQ} + x_P*Z_{mQ})^2
        let mut t0 = affine_xP * &xmQ.X;    // = x_P*X_{mQ}
        let mut YmQ = &xmQ.Z - &t0;         // = Z_{mQ} - x_P*X_{mQ}
        let mut t1 = affine_xP * &xmQ.Z;    // = x_P*Z_{mQ}
        t0 = &xmQ.X - &t1;                  // = X_{mQ} - x_P*Z_{mQ}
        YmQ = &YmQ * &t0;                   // = (Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})
        YmQ = &YmQ * &xm1Q.Z;               // = (Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})*Z_{m1Q}
        t1 = (&t1 + &xmQ.X).square();       // = (X_{mQ} + x_P*Z_{mQ})^2
        t1 = &t1 * &xm1Q.X;                 // = X_{m1Q}*(X_{mQ} + x_P*Z_{mQ})^2
        YmQ = &YmQ - &t1;                   // = Y_{mQ}

        // Z_{mQ} = -2*(Z_{mQ}^2 * Z_{m1Q} * y_P)
        t0 = &(&xmQ.Z * &xm1Q.Z) * affine_yP;   // = Z_{mQ} * Z_{m1Q} * y_P
        t0 = -(&t0);                            // = -1*(Z_{mQ} * Z_{m1Q} * y_P)
        t0 = &t0 + &t0;                         // = -2*(Z_{mQ} * Z_{m1Q} * y_P)
        let ZmQ = &xmQ.Z * &t0;                 // = -2*(Z_{mQ}^2 * Z_{m1Q} * y_P)

        // We added terms to the denominator Z_{mQ}, so multiply them to X_{mQ}.
	    // X_{mQ} = -2*X_{mQ}*Z_{mQ}*Z_{m1Q}*y_P
        let XmQ = &xmQ.X * &t0;

        // Now compute x(P + [m]Q) = (X_Ra + i*X_Rb : Z_R)
        let mut XRb = &ZmQ.square() * &YmQ; // = Y_{mQ} * Z_{mQ}^2
        XRb = &XRb * affine_yP;             // = Y_{mQ} * y_P * Z_{mQ}^2
        XRb = &XRb + &XRb;                  // = 2 * Y_{mQ} * y_P * Z_{mQ}^2
        XRb = -(&XRb);                      // = -2 * Y_{mQ} * y_P * Z_{mQ}^2

        t0 = (affine_yP * &ZmQ).square();   // = (y_P * Z_{mQ})^2
        t1 = YmQ.square();                  // = Y_{mQ}^2
        let mut XRa = &t0 - &t1;            // = (y_P * Z_{mQ})^2 - Y_{mQ}^2
        XRa = &XRa * &ZmQ;                  // = Z_{mQ}*((y_P * Z_{mQ})^2 - Y_{mQ}^2)
        t0 = affine_xP * &ZmQ;              // = x_P * Z_{mQ}
        t1 = &XmQ + &t0;                    // = X_{mQ} + x_P*Z_{mQ}
        t0 = &XmQ - &t0;                    // = X_{mQ} - x_P*Z_{mQ}
        t0 = t0.square();                   // = (X_{mQ} - x_P*Z_{mQ})^2
        t1 = &t1 * &t0;                     // = (X_{mQ} + x_P*Z_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2
        XRa = &XRa - &t1;                   // = Z_{mQ}*((y_P*Z_{mQ})^2 - Y_{mQ}^2) - (X_{mQ} + x_P*Z_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2

        let ZR = &ZmQ * &t0;                // = Z_{mQ}*(X_{mQ} - x_P*Z_{mQ})^2

        let mut xR = ProjectivePoint{ X: ExtensionFieldElement::zero(), Z: ExtensionFieldElement::zero() };
        xR.X.A = XRa.A;
        xR.X.B = XRb.A;
        xR.Z.A = ZR.A;

        xR
    }
}

// A point on the projective line P^1(F_p).
//
// This represents a point on the (Kummer line) of the prime-field subgroup of
// the base curve E_0(F_p), defined by E_0 : y^2 = x^3 + x.
#[derive(Copy, Clone, PartialEq)]
struct ProjectivePrimeFieldPoint {
    X: PrimeFieldElement,
    Z: PrimeFieldElement,
}

impl ConditionallySwappable for ProjectivePrimeFieldPoint {
    fn conditional_swap(&mut self, other: &mut ProjectivePrimeFieldPoint, choice: u8) {
        (&mut self.X).conditional_swap(&mut other.X, choice);
        (&mut self.Z).conditional_swap(&mut other.Z, choice);
    }
}

impl Debug for ProjectivePrimeFieldPoint {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "ProjectivePrimeFieldPoint(X: {:?}\nZ: {:?})", &self.X, &self.Z)
    }
}

#[cfg(test)]
impl Arbitrary for ProjectivePrimeFieldPoint {
    fn arbitrary<G: Gen>(g: &mut G) -> ProjectivePrimeFieldPoint {
        let x = g.gen::<PrimeFieldElement>();
        let z = g.gen::<PrimeFieldElement>();
        ProjectivePrimeFieldPoint{ X: x, Z: z }
    }
}

impl ProjectivePrimeFieldPoint {
    // Creates a new zero ProjectivePrimeFieldPoint.
    pub fn new() -> ProjectivePrimeFieldPoint {
        ProjectivePrimeFieldPoint{ X: PrimeFieldElement::zero(), Z: PrimeFieldElement::zero() }
    }

    pub fn from_affine(x: &PrimeFieldElement) -> ProjectivePrimeFieldPoint {
        ProjectivePrimeFieldPoint{
            X: *x,
            Z: PrimeFieldElement::one()
        }
    }

    pub fn to_affine(&self) -> PrimeFieldElement {
        let affine_x = &self.Z.inv() * &self.X;
        affine_x
    }
    // Returns true if both sides are equal. Takes variable time.
    pub fn vartime_eq(&self, _rhs: &ProjectivePrimeFieldPoint) -> bool {
        let t0 = &self.X * &_rhs.Z;
        let t1 = &self.Z * &_rhs.X;
        t0.vartime_eq(&t1)
    }
    // Given xP = x(P), xQ = x(Q), and xPmQ = x(P-Q), compute xR = x(P+Q).
    fn add(&self, xQ: &ProjectivePrimeFieldPoint, xPmQ: &ProjectivePrimeFieldPoint) -> 
           ProjectivePrimeFieldPoint
    {
        let xP = *self;
        // Algorithm 1 of Costello-Smith.
        let mut v0 = &xP.X + &xP.Z;         // X_P + Z_P
        let v1 = &(&xQ.X - &xQ.Z) * &v0;    // (X_Q - Z_Q)(X_P + Z_P)
        v0 = &xP.X - &xP.Z;                 // X_P - Z_P
        let v2 = &(&xQ.X + &xQ.Z) * &v0;    // (X_Q + Z_Q)(X_P - Z_P)
        let v3 = (&v1 + &v2).square();      // 4(X_Q X_P - Z_Q Z_P)^2
        let v4 = (&v1 - &v2).square();      // 4(X_Q Z_P - Z_Q X_P)^2
        v0 = &xPmQ.Z * &v3;                 // 4X_{P-Q}(X_Q X_P - Z_Q Z_P)^2
        let z = &xPmQ.X * &v4;              // 4Z_{P-Q}(X_Q Z_P - Z_Q X_P)^2
        let x = v0;

        ProjectivePrimeFieldPoint{ X: x, Z: z }
    }
    // Given xP = x(P) and cached curve parameter aPlus2Over4 = (a+2)/4, compute xQ = x([2]P).
    //
    // Note that we don't use projective curve coefficients here because we only
    // ever use a fixed curve (in our case, the base curve E_0).
    fn double(&self, aPlus2Over4: &PrimeFieldElement) -> ProjectivePrimeFieldPoint {
        let xP = *self;
        // Algorithm 2 of Costello-Smith
        let v1 = (&xP.X + &xP.Z).square();      // (X+Z)^2
        let v2 = (&xP.X - &xP.Z).square();      // (X-Z)^2
        let xz4 = &v1 - &v2;                    // 4XZ = (X+Z)^2 - (X-Z)^2
        let x = &v1 * &v2;                      // (X+Z)^2(X-Z)^2
        let mut v3 = &xz4 * aPlus2Over4;        // 4XZ((a+2)/4)
        v3 = &v3 + &v2;                         // 4XZ((a+2)/4) + (X-Z)^2
        let z = &v3 * &xz4;                     // (4XZ((a+2)/4) + (X-Z)^2)4XZ
        // Now (xQ.x : xQ.z)
        //   = ((X+Z)^2(X-Z)^2 : (4XZ((a + 2)/4) + (X-Z)^2)4XZ )
        ProjectivePrimeFieldPoint{ X: x, Z: z }
    }
    // dbl_add method calculates the x-coordinate of 2P and P+Q from the x-coordinate of P, Q and P-Q.
    // Assumptions:
    // 	  aPlus2Over2 = (A+2)/4.
    //    z(P-Q) = 1,  the Z-coordinate of P-Q is equal to 1.
    // Cost: 6M+4S+8A in Fp
    fn dbl_add(&self, xQ: &ProjectivePrimeFieldPoint, xPmQ: &ProjectivePrimeFieldPoint, aPlus2Over4: &PrimeFieldElement) ->
              (ProjectivePrimeFieldPoint, ProjectivePrimeFieldPoint)
    {
        let xP = *self;
        let x1 = &xPmQ.X;
        let (x2, z2) = (&xP.X, &xP.Z);
        let (x3, z3) = (&xQ.X, &xQ.Z);

        let mut t0 = x2 + z2;   // A = x2+z2
        let mut t1 = x2 - z2;   // B = x2-z2
        let mut t3 = x3 + z3;   // C = x3+z3
        let mut t2 = x3 - z3;   // D = x3-z3
        t2 = &t2 * &t0;         // DA = D*A
        t3 = &t3 * &t1;         // CB = C*B

        let mut x = &t2 + &t3;  // x5 = DA+CB
        let mut z = &t2 - &t3;  // z5 = DA-CB
        x = x.square();         // x5 = (DA+CB)^2
        z = z.square();         // z5 = (DA-CB)^2
        z = &z * x1;            // z5 = x1*(DA-CB)^2
        let xPaddQ = ProjectivePrimeFieldPoint{ X: x, Z: z };

        t0 = t0.square();          // t0 = AA = A^2
        t1 = t1.square();          // t1 = BB = B^2
        x = &t0 * &t1;             // x4 = AA*BB
        t0 = &t0 - &t1;            // t2 = E = AA-BB
        z = &t0 * aPlus2Over4;     // z4 = ((A+2C)/4)*E
        z = &z + &t1;              // z4 = BB+((A+2C)/4)*E
        z = &z * &t0;              // z4 = E*(BB+((A+2C)/4)*E)
        let x2P = ProjectivePrimeFieldPoint{ X: x, Z: z };

        (x2P, xPaddQ)
    }
    // Given x(P) and a scalar m in little-endian bytes, compute x([m]P), x([m+1]P) 
    // using the Montgomery ladder. This is described in Algorithm 8 of Costello-Smith.
    //
    // The extra value x([m+1]P) is returned to allow y-coordinate recovery, otherwise, 
    // it can be ignored.
    //
    // This function's execution time is dependent only on the byte-length of the input
    // scalar. All scalars of the same input length execute in uniform time.
    // The scalar can be padded with zero bytes to ensure a uniform length.
    fn scalar_mul_prime_field(xP: &ProjectivePrimeFieldPoint, aPlus2Over4: &PrimeFieldElement, scalar: &[u8]) -> 
                             (ProjectivePrimeFieldPoint, ProjectivePrimeFieldPoint)
    {
        //let xP = *self;
        let mut x0 = ProjectivePrimeFieldPoint{ X: PrimeFieldElement::one(), Z: PrimeFieldElement::zero() };
        let mut x1 = *xP; // If we use self, changei it back to xP, removing *.

        // Iterate over the bits of the scalar, top to bottom.
        let mut prev_bit: u8 = 0;
        for i in (0..scalar.len()).rev() {
            let scalar_byte = scalar[i];
            for j in (0..8).rev() {
                let bit = (scalar_byte >> (j as u32)) & 0x1;
                (&mut x0).conditional_swap(&mut x1, (bit ^ prev_bit));
                assign!{(x0, x1) = x0.dbl_add(&x1, xP, aPlus2Over4)};
                prev_bit = bit;
            }
        }
        // Now prev_bit is the lowest bit of the scalar.
        (&mut x0).conditional_swap(&mut x1, prev_bit);
        (x0, x1)
    }
}

// Sage script for generating test vectors:
// sage: p = 2^372 * 3^239 - 1; Fp = GF(p)
// sage: R.<x> = Fp[]
// sage: Fp2 = Fp.extension(x^2 + 1, 'i')
// sage: i = Fp2.gen()
// sage: A = 4385300808024233870220415655826946795549183378139271271040522089756750951667981765872679172832050962894122367066234419550072004266298327417513857609747116903999863022476533671840646615759860564818837299058134292387429068536219*i + 1408083354499944307008104531475821995920666351413327060806684084512082259107262519686546161682384352696826343970108773343853651664489352092568012759783386151707999371397181344707721407830640876552312524779901115054295865393760
// sage: C = 933177602672972392833143808100058748100491911694554386487433154761658932801917030685312352302083870852688835968069519091048283111836766101703759957146191882367397129269726925521881467635358356591977198680477382414690421049768*i + 9088894745865170214288643088620446862479558967886622582768682946704447519087179261631044546285104919696820250567182021319063155067584445633834024992188567423889559216759336548208016316396859149888322907914724065641454773776307
// sage: E = EllipticCurve(Fp2, [0,A/C,0,1,0])
// sage: X, Y, Z = (8172151271761071554796221948801462094972242987811852753144865524899433583596839357223411088919388342364651632180452081960511516040935428737829624206426287774255114241789158000915683252363913079335550843837650671094705509470594*i + 9326574858039944121604015439381720195556183422719505497448541073272720545047742235526963773359004021838961919129020087515274115525812121436661025030481584576474033630899768377131534320053412545346268645085054880212827284581557, 2381174772709336084066332457520782192315178511983342038392622832616744048226360647551642232950959910067260611740876401494529727990031260499974773548012283808741733925525689114517493995359390158666069816204787133942283380884077*i + 5378956232034228335189697969144556552783858755832284194802470922976054645696324118966333158267442767138528227968841257817537239745277092206433048875637709652271370008564179304718555812947398374153513738054572355903547642836171, 1)
// sage: P = E((X,Y,Z))
// sage: X2, Y2, Z2 = 2*P
// sage: X3, Y3, Z3 = 3*P
// sage: m = 96550223052359874398280314003345143371473380422728857598463622014420884224892
//
#[cfg(test)]
mod test {
    use super::*;

    // A = 4385300808024233870220415655826946795549183378139271271040522089756750951667981765872679172832050962894122367066234419550072004266298327417513857609747116903999863022476533671840646615759860564818837299058134292387429068536219*i + 1408083354499944307008104531475821995920666351413327060806684084512082259107262519686546161682384352696826343970108773343853651664489352092568012759783386151707999371397181344707721407830640876552312524779901115054295865393760
    const CURVE_A: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0x8319eb18ca2c435e, 0x3a93beae72cd0267, 0x5e465e1f72fd5a84, 0x8617fa4150aa7272, 0x887da24799d62a13, 0xb079b31b3c7667fe, 0xc4661b150fa14f2e, 0xd4d2b2967bc6efd6, 0x854215a8b7239003, 0x61c5302ccba656c2, 0xf93194a27d6f97a2, 0x1ed9532bca75]),
                                                                   B: Fp751Element([0xb6f541040e8c7db6, 0x99403e7365342e15, 0x457e9cee7c29cced, 0x8ece72dc073b1d67, 0x6e73cef17ad28d28, 0x7aed836ca317472, 0x89e1de9454263b54, 0x745329277aa0071b, 0xf623dfc73bc86b9b, 0xb8e3c1d8a9245882, 0x6ad0b3d317770bec, 0x5b406e8d502b]) };

    // C = 933177602672972392833143808100058748100491911694554386487433154761658932801917030685312352302083870852688835968069519091048283111836766101703759957146191882367397129269726925521881467635358356591977198680477382414690421049768*i + 9088894745865170214288643088620446862479558967886622582768682946704447519087179261631044546285104919696820250567182021319063155067584445633834024992188567423889559216759336548208016316396859149888322907914724065641454773776307
    const CURVE_C: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0x4fb2358bbf723107, 0x3a791521ac79e240, 0x283e24ef7c4c922f, 0xc89baa1205e33cc, 0x3031be81cff6fee1, 0xaf7a494a2f6a95c4, 0x248d251eaac83a1d, 0xc122fca1e2550c88, 0xbc0451b11b6cfd3d, 0x9c0a114ab046222c, 0x43b957b32f21f6ea, 0x5b9c87fa61de]),
                                                                  B: Fp751Element([0xacf142afaac15ec6, 0xfd1322a504a071d5, 0x56bb205e10f6c5c6, 0xe204d2849a97b9bd, 0x40b0122202fe7f2e, 0xecf72c6fafacf2cb, 0x45dfc681f869f60a, 0x11814c9aff4af66c, 0x9278b0c4eea54fe7, 0x9a633d5baf7f2e2e, 0x69a329e6f1a05112, 0x1d874ace23e4]) };
    
    const CURVE: ProjectiveCurveParameters = ProjectiveCurveParameters{ A: CURVE_A, C: CURVE_C };

    // x(P) = 8172151271761071554796221948801462094972242987811852753144865524899433583596839357223411088919388342364651632180452081960511516040935428737829624206426287774255114241789158000915683252363913079335550843837650671094705509470594*i + 9326574858039944121604015439381720195556183422719505497448541073272720545047742235526963773359004021838961919129020087515274115525812121436661025030481584576474033630899768377131534320053412545346268645085054880212827284581557
    const AFFINE_XP: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0xe8d05f30aac47247, 0x576ec00c55441de7, 0xbf1a8ec5fe558518, 0xd77cb17f77515881, 0x8e9852837ee73ec4, 0x8159634ad4f44a6b, 0x2e4eb5533a798c5, 0x9be8c4354d5bc849, 0xf47dc61806496b84, 0x25d0e130295120e0, 0xdbef54095f8139e3, 0x5a724f20862c]),
                                                                    B: Fp751Element([0x3ca30d7623602e30, 0xfb281eddf45f07b7, 0xd2bf62d5901a45bc, 0xc67c9baf86306dd2, 0x4e2bd93093f538ca, 0xcfd92075c25b9cbe, 0xceafe9a3095bcbab, 0x7d928ad380c85414, 0x37c5f38b2afdc095, 0x75325899a7b779f4, 0xf130568249f20fdd, 0x178f264767d1]) };
    
    // x([2]P) = 1476586462090705633631615225226507185986710728845281579274759750260315746890216330325246185232948298241128541272709769576682305216876843626191069809810990267291824247158062860010264352034514805065784938198193493333201179504845*i + 3623708673253635214546781153561465284135688791018117615357700171724097420944592557655719832228709144190233454198555848137097153934561706150196041331832421059972652530564323645509890008896574678228045006354394485640545367112224
    const AFFINE_XP2: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0x2a77afa8576ce979, 0xab1360e69b0aeba0, 0xd79e3e3cbffad660, 0x5fd0175aa10f106b, 0x1800ebafce9fbdbc, 0x228fc9142bdd6166, 0x867cf907314e34c3, 0xa58d18c94c13c31c, 0x699a5bc78b11499f, 0xa29fc29a01f7ccf1, 0x6c69c0c5347eebce, 0x38ecee0cc57]),
                                                                     B: Fp751Element([0x43607fd5f4837da0, 0x560bad4ce27f8f4a, 0x2164927f8495b4dd, 0x621103fdb831a997, 0xad740c4eea7db2db, 0x2cde0442205096cd, 0x2af51a70ede8324e, 0x41a4e680b9f3466, 0x5481f74660b8f476, 0xfcb2f3e656ff4d18, 0x42e3ce0837171acc, 0x44238c30530c]) };

    // x([3]P) = 9351941061182433396254169746041546943662317734130813745868897924918150043217746763025923323891372857734564353401396667570940585840576256269386471444236630417779544535291208627646172485976486155620044292287052393847140181703665*i + 9010417309438761934687053906541862978676948345305618417255296028956221117900864204687119686555681136336037659036201780543527957809743092793196559099050594959988453765829339642265399496041485088089691808244290286521100323250273
    const AFFINE_XP3: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0x2096e3f23feca947, 0xf36f635aa4ad8634, 0xdae3b1c6983c5e9a, 0xe08df6c262cb74b4, 0xd2ca4edc37452d3d, 0xfb5f3fe42f500c79, 0x73740aa3abc2b21f, 0xd535fd869f914cca, 0x4a558466823fb67f, 0x3e50a7a0e3bfc715, 0xf43c6da9183a132f, 0x61aca1e1b8b9]),
                                                                     B: Fp751Element([0x1e54ec26ea5077bd, 0x61380572d8769f9a, 0xc615170684f59818, 0x6309c3b93e84ef6e, 0x33c74b1318c3fcd0, 0xfe8d7956835afb14, 0x2d5a7b55423c1ecc, 0x869db67edfafea68, 0x1292632394f0a628, 0x10bba48225bfd141, 0x6466c28b408daba, 0x63cacfdb7c43]) };

    // x([a]P) = 7893578558852400052689739833699289348717964559651707250677393044951777272628231794999463214496545377542328262828965953246725804301238040891993859185944339366910592967840967752138115122568615081881937109746463885908097382992642*i + 8293895847098220389503562888233557012043261770526854885191188476280014204211818299871679993460086974249554528517413590157845430186202704783785316202196966198176323445986064452630594623103149383929503089342736311904030571524837
    const AFFINE_XAP: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0x2112f3c7d7f938bb, 0x704a677f0a4df08f, 0x825370e31fb4ef00, 0xddbf79b7469f902, 0x27640c899ea739fd, 0xfb7b8b19f244108e, 0x546a6679dd3baebc, 0xe9f0ecf398d5265f, 0x223d2b350e75e461, 0x84b322a0b6aff016, 0xfabe426f539f8b39, 0x4507a0604f50]),
                                                                     B: Fp751Element([0xac77737e5618a5fe, 0xf91c0e08c436ca52, 0xd124037bc323533c, 0xc9a772bf52c58b63, 0x3b30c8f38ef6af4d, 0xb9eed160e134f36e, 0x24e3836393b25017, 0xc828be1b11baf1d9, 0x7b7dab585df50e93, 0x1ca3852c618bd8e0, 0x4efa73bcb359fa00, 0x50b6a923c2d4]) };

    // m = 96550223052359874398280314003345143371473380422728857598463622014420884224892
    const M_SCALAR_BYTES: [u8; 32] = [124, 123, 149, 250, 180, 117, 108, 72, 140, 23, 85, 180, 73, 245, 30, 163, 11, 49, 240, 164, 166, 129, 173, 148, 81, 17, 231, 245, 91, 125, 117, 213];

    // Since function calls in constants and statics are limited to constant functions in Rust, we define it here and assign to other consts when needed.
    const EXTENSION_FIELD_ELEMENT_ONE: ExtensionFieldElement = ExtensionFieldElement {
            A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
            B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    };

    const THREE_POINT_LADDER_INPUTS: [ProjectivePoint; 3] = [
        // x(P)
        ProjectivePoint{
            X: ExtensionFieldElement{ A: Fp751Element([0xe8d05f30aac47247, 0x576ec00c55441de7, 0xbf1a8ec5fe558518, 0xd77cb17f77515881, 0x8e9852837ee73ec4, 0x8159634ad4f44a6b, 0x2e4eb5533a798c5, 0x9be8c4354d5bc849, 0xf47dc61806496b84, 0x25d0e130295120e0, 0xdbef54095f8139e3, 0x5a724f20862c]), 
                                      B: Fp751Element([0x3ca30d7623602e30, 0xfb281eddf45f07b7, 0xd2bf62d5901a45bc, 0xc67c9baf86306dd2, 0x4e2bd93093f538ca, 0xcfd92075c25b9cbe, 0xceafe9a3095bcbab, 0x7d928ad380c85414, 0x37c5f38b2afdc095, 0x75325899a7b779f4, 0xf130568249f20fdd, 0x178f264767d1]) },
            Z: EXTENSION_FIELD_ELEMENT_ONE,
        },
        // x(Q)
        ProjectivePoint{
            X: ExtensionFieldElement{ A: Fp751Element([0x2b71a2a93ad1e10e, 0xf0b9842a92cfb333, 0xae17373615a27f5c, 0x3039239f428330c4, 0xa0c4b735ed7dcf98, 0x6e359771ddf6af6a, 0xe986e4cac4584651, 0x8233a2b622d5518, 0xbfd67bf5f06b818b, 0xdffe38d0f5b966a6, 0xa86b36a3272ee00a, 0x193e2ea4f68f]), 
                                      B: Fp751Element([0x5a0f396459d9d998, 0x479f42250b1b7dda, 0x4016b57e2a15bf75, 0xc59f915203fa3749, 0xd5f90257399cf8da, 0x1fb2dadfd86dcef4, 0x600f20e6429021dc, 0x17e347d380c57581, 0xc1b0d5fa8fe3e440, 0xbcf035330ac20e8, 0x50c2eb5f6a4f03e6, 0x86b7c4571]) },
            Z: EXTENSION_FIELD_ELEMENT_ONE,
        },
        // x(P-Q)
        ProjectivePoint{
            X: ExtensionFieldElement{ A: Fp751Element([0x4aafa9f378f7b5ff, 0x1172a683aa8eee0, 0xea518d8cbec2c1de, 0xe191bcbb63674557, 0x97bc19637b259011, 0xdbeae5c9f4a2e454, 0x78f64d1b72a42f95, 0xe71cb4ea7e181e54, 0xe4169d4c48543994, 0x6198c2286a98730f, 0xd21d675bbab1afa5, 0x2e7269fce391]), 
                                      B: Fp751Element([0x23355783ce1d0450, 0x683164cf4ce3d93f, 0xae6d1c4d25970fd8, 0x7807007fb80b48cf, 0xa005a62ec2bbb8a2, 0x6b5649bd016004cb, 0xbb1a13fa1330176b, 0xbf38e51087660461, 0xe577fddc5dd7b930, 0x5f38116f56947cd3, 0x3124f30b98c36fde, 0x4ca9b6e6db37]) },
            Z: EXTENSION_FIELD_ELEMENT_ONE,
        },
    ];

    #[test]
    fn one() {
        let tmp = &EXTENSION_FIELD_ELEMENT_ONE * &AFFINE_XP;
        assert!(tmp.vartime_eq(&AFFINE_XP), "Not equal 1");
    }

    #[test]
    fn jinvariant() {
        let j = CURVE.j_invariant();
        // Computed using Sage:
        // j = 3674553797500778604587777859668542828244523188705960771798425843588160903687122861541242595678107095655647237100722594066610650373491179241544334443939077738732728884873568393760629500307797547379838602108296735640313894560419*i + 3127495302417548295242630557836520229396092255080675419212556702820583041296798857582303163183558315662015469648040494128968509467224910895884358424271180055990446576645240058960358037224785786494172548090318531038910933793845
        let known_j = ExtensionFieldElement{
            A: Fp751Element([0xc7a8921c1fb23993, 0xa20aea321327620b, 0xf1caa17ed9676fa8, 0x61b780e6b1a04037, 0x47784af4c24acc7a, 0x83926e2e300b9adf, 0xcd891d56fae5b66, 0x49b66985beb733bc, 0xd4bcd2a473d518f, 0xe242239991abe224, 0xa8af5b20f98672f8, 0x139e4d4e4d98]),
            B: Fp751Element([0xb5b52a21f81f359, 0x715e3a865db6d920, 0x9bac2f9d8911978b, 0xef14acd8ac4c1e3d, 0xe81aacd90cfb09c8, 0xaf898288de4a09d9, 0xb85a7fb88c5c4601, 0x2c37c3f1dd303387, 0x7ad3277fe332367c, 0xd4cbee7f25a8e6f8, 0x36eacbe979eaeffa, 0x59eb5a13ac33]),
        };

        assert!(j.vartime_eq(&known_j), "Computed incorrect j-invariant: found\n{:?}\nexpected\n{:?}", j, known_j);
    }

    #[test]
    fn projective_point_vartime_eq() {
        let xP = ProjectivePoint{ X: AFFINE_XP, Z: EXTENSION_FIELD_ELEMENT_ONE };
        let mut xQ = xP;
        // Scale xQ, which results in the same projective point.
        xQ.X = &xQ.X * &CURVE_A;
        xQ.Z = &xQ.Z * &CURVE_A;

        assert!(xQ.vartime_eq(&xP), "Expected the scaled point to be equal to the original");
    }

    #[test]
    fn point_double_versus_sage() {
        let xP = ProjectivePoint{ X: AFFINE_XP, Z: EXTENSION_FIELD_ELEMENT_ONE };
        let xQ = xP.pow2k(&CURVE, 1);
        let affine_xQ = xQ.to_affine();

        assert!(affine_xQ.vartime_eq(&AFFINE_XP2), "\nExpected\n{:?}\nfound\n{:?}", AFFINE_XP2, affine_xQ);
    }

    #[test]
    fn point_triple_versus_sage() {
        let xP = ProjectivePoint{ X: AFFINE_XP, Z: EXTENSION_FIELD_ELEMENT_ONE };
        let xQ = xP.pow3k(&CURVE, 1);
        let affine_xQ = xQ.to_affine();

        assert!(affine_xQ.vartime_eq(&AFFINE_XP3), "\nExpected\n{:?}\nfound\n{:?}", AFFINE_XP3, affine_xQ);
    }

    #[test]
    fn point_pow2k_versus_scalar_mul() {
        let byte = [32u8; 1];
        let xP = ProjectivePoint{ X: AFFINE_XP, Z: EXTENSION_FIELD_ELEMENT_ONE };
        let xQ = xP.pow2k(&CURVE, 5);              // = x([32]P)
        let affine_xQ = xQ.to_affine();
        let xR = xP.scalar_mul(&CURVE, &byte[..]); // = x([32]P)
        let affine_xR = xR.to_affine();

        assert!(affine_xQ.vartime_eq(&affine_xR), "\nExpected\n{:?}\nfound\n{:?}", affine_xQ, affine_xR);
    }

    #[test]
    fn scalar_mul_versus_sage() {
        let mut xP = ProjectivePoint{ X: AFFINE_XP, Z: ExtensionFieldElement::one() };
        xP = xP.scalar_mul(&CURVE, &M_SCALAR_BYTES[..]); // = x([m]P)
        let affine_xQ = xP.to_affine();

        assert!(AFFINE_XAP.vartime_eq(&affine_xQ), "\nExpected\n{:?}\nfound\n{:?}", AFFINE_XAP, affine_xQ);
    }

    #[test]
    fn recover_curve_params() {
        // Created using old public key generation code that output the a value:
        let a = ExtensionFieldElement{ A: Fp751Element([0x9331d9c5aaf59ea4, 0xb32b702be4046931, 0xcebb333912ed4d34, 0x5628ce37cd29c7a2, 0xbeac5ed48b7f58e, 0x1fb9d3e281d65b07, 0x9c0cfacc1e195662, 0xae4bce0f6b70f7d9, 0x59e4e63d43fe71a0, 0xef7ce57560cc8615, 0xe44a8fb7901e74e8, 0x69d13c8366d1]), 
                                       B: Fp751Element([0xf6da1070279ab966, 0xa78fb0ce7268c762, 0x19b40f044a57abfa, 0x7ac8ee6160c0c233, 0x93d4993442947072, 0x757d2b3fa4e44860, 0x73a920f8c4d5257, 0x2031f1b054734037, 0xdefaa1d2406555cd, 0x26f9c70e1496be3d, 0x5b3f335a0a4d0976, 0x13628b2e9c59]) };
        let affine_xP = ExtensionFieldElement{ A: Fp751Element([0xea6b2d1e2aebb250, 0x35d0b205dc4f6386, 0xb198e93cb1830b8d, 0x3b5b456b496ddcc6, 0x5be3f0d41132c260, 0xce5f188807516a00, 0x54f3e7469ea8866d, 0x33809ef47f36286, 0x6fa45f83eabe1edb, 0x1b3391ae5d19fd86, 0x1e66daf48584af3f, 0xb430c14aaa87]), 
                                               B: Fp751Element([0x97b41ebc61dcb2ad, 0x80ead31cb932f641, 0x40a940099948b642, 0x2a22fd16cdc7fe84, 0xaabf35b17579667f, 0x76c1d0139feb4032, 0x71467e1e7b1949be, 0x678ca8dadd0d6d81, 0x14445daea9064c66, 0x92d161eab4fa4691, 0x8dfbb01b6b238d36, 0x2e3718434e4e]) };
        let affine_xQ = ExtensionFieldElement{ A: Fp751Element([0xb055cf0ca1943439, 0xa9ff5de2fa6c69ed, 0x4f2761f934e5730a, 0x61a1dcaa1f94aa4b, 0xce3c8fadfd058543, 0xeac432aaa6701b8e, 0x8491d523093aea8b, 0xba273f9bd92b9b7f, 0xd8f59fd34439bb5a, 0xdc0350261c1fe600, 0x99375ab1eb151311, 0x14d175bbdbc5]), 
                                               B: Fp751Element([0xffb0ef8c2111a107, 0x55ceca3825991829, 0xdbf8a1ccc075d34b, 0xb8e9187bd85d8494, 0x670aa2d5c34a03b0, 0xef9fe2ed2b064953, 0xc911f5311d645aee, 0xf4411f409e410507, 0x934a0a852d03e1a8, 0xe6274e67ae1ad544, 0x9f4bc563c69a87bc, 0x6f316019681e]) };
        let affine_xQmP = ExtensionFieldElement{ A: Fp751Element([0x6ffb44306a153779, 0xc0ffef21f2f918f3, 0x196c46d35d77f778, 0x4a73f80452edcfe6, 0x9b00836bce61c67f, 0x387879418d84219e, 0x20700cf9fc1ec5d1, 0x1dfe2356ec64155e, 0xf8b9e33038256b1c, 0xd2aaf2e14bada0f0, 0xb33b226e79a4e313, 0x6be576fad4e5]), 
                                                 B: Fp751Element([0x7db5dbc88e00de34, 0x75cc8cb9f8b6e11e, 0x8c8001c04ebc52ac, 0x67ef6c981a0b5a94, 0xc3654fbe73230738, 0xc6a46ee82983ceca, 0xed1aa61a27ef49f0, 0x17fe5a13b0858fe0, 0x9ae0ca945a4c6b3c, 0x234104a218ad8878, 0xa619627166104394, 0x556a01ff2e7e]) };
        
        let curve_params = ProjectiveCurveParameters::recover_curve_parameters(&affine_xP, &affine_xQ, &affine_xQmP);
        let tmp = &curve_params.C.inv() * &curve_params.A;

        assert!(tmp.vartime_eq(&a), "\nExpected\n{:?}\nfound\n{:?}", a, tmp);
    }

    #[test]
    fn three_point_ladder_versus_sage() {
        let xR = ProjectivePoint::three_point_ladder(&THREE_POINT_LADDER_INPUTS[0], &THREE_POINT_LADDER_INPUTS[1], &THREE_POINT_LADDER_INPUTS[2], &CURVE, &M_SCALAR_BYTES[..]);
        let affine_xR = xR.to_affine();
        let sage_affine_xR = ExtensionFieldElement{ A: Fp751Element([0x729465ba800d4fd5, 0x9398015b59e514a1, 0x1a59dd6be76c748e, 0x1a7db94eb28dd55c, 0x444686e680b1b8ec, 0xcc3d4ace2a2454ff, 0x51d3dab4ec95a419, 0xc3b0f33594acac6a, 0x9598a74e7fd44f8a, 0x4fbf8c638f1c2e37, 0x844e347033052f51, 0x6cd6de3eafcf]), 
                                                    B: Fp751Element([0x85da145412d73430, 0xd83c0e3b66eb3232, 0xd08ff2d453ec1369, 0xa64aaacfdb395b13, 0xe9cba211a20e806e, 0xa4f80b175d937cfc, 0x556ce5c64b1f7937, 0xb59b39ea2b3fdf7a, 0xc2526b869a4196b3, 0x8dad90bca9371750, 0xdfb4a30c9d9147a2, 0x346d2130629b]) };
        
        assert!(affine_xR.vartime_eq(&sage_affine_xR), "\nExpected\n{:?}\nfound\n{:?}", sage_affine_xR, affine_xR);
    }

    #[test]
    fn right_to_left_ladder_versus_sage() {
        let xR = ProjectivePoint::right_to_left_ladder(&THREE_POINT_LADDER_INPUTS[0], &THREE_POINT_LADDER_INPUTS[1], &THREE_POINT_LADDER_INPUTS[2], &CURVE, &M_SCALAR_BYTES[..]);
        let affine_xR = xR.to_affine();
        let sage_affine_xR = ExtensionFieldElement{ A: Fp751Element([0x729465ba800d4fd5, 0x9398015b59e514a1, 0x1a59dd6be76c748e, 0x1a7db94eb28dd55c, 0x444686e680b1b8ec, 0xcc3d4ace2a2454ff, 0x51d3dab4ec95a419, 0xc3b0f33594acac6a, 0x9598a74e7fd44f8a, 0x4fbf8c638f1c2e37, 0x844e347033052f51, 0x6cd6de3eafcf]), 
                                                    B: Fp751Element([0x85da145412d73430, 0xd83c0e3b66eb3232, 0xd08ff2d453ec1369, 0xa64aaacfdb395b13, 0xe9cba211a20e806e, 0xa4f80b175d937cfc, 0x556ce5c64b1f7937, 0xb59b39ea2b3fdf7a, 0xc2526b869a4196b3, 0x8dad90bca9371750, 0xdfb4a30c9d9147a2, 0x346d2130629b]) };
        
        assert!(affine_xR.vartime_eq(&sage_affine_xR), "\nExpected\n{:?}\nfound\n{:?}", sage_affine_xR, affine_xR);
    }

    #[test]
    fn point_triple_versus_add_double() {
        fn triple_equals_add_double(curve: ProjectiveCurveParameters, P: ProjectivePoint) -> bool {
            let cached_params = curve.cached_params();
            let cached_triple_params = curve.cached_triple_params();
            let P2 = P.double(&cached_params);        // = x([2]P)
            let P3 = P.triple(&cached_triple_params); // = x([3]P)
            let P2plusP = P2.add(&P, &P);             // = x([2]P + P)

            P3.vartime_eq(&P2plusP)
        }
        QuickCheck::new().quickcheck(triple_equals_add_double as fn(ProjectiveCurveParameters, ProjectivePoint) -> bool);
    }

    #[test]
    fn scalar_mul_prime_field_and_coordinate_recovery_versus_sage_generated_torsion_points() {
        // x((11,...)) = 11
        let x11 = ProjectivePrimeFieldPoint{
            X: PrimeFieldElement{ A: Fp751Element([0x192a73, 0x0, 0x0, 0x0, 0x0, 0xe6f0000000000000, 0x19024ab93916c5c3, 0x1dcd18cf68876318, 0x7d8c830e0c47ba23, 0x3588ea6a9388299a, 0x8259082aa8e3256c, 0x33533f160446]) },
            Z: PrimeFieldElement::one(),
        };
        // y((11,...)) = oddsqrt(11^3 + 11)
        let y11 = PrimeFieldElement{ A: Fp751Element([0xd38a264df57f3c8a, 0x9c0450d25042dcdf, 0xaf1ab7be7bbed0b6, 0xa307981c42b29630, 0x845a7e79e0fa2ecb, 0x7ef77ef732108f55, 0x97b5836751081f0d, 0x59e3d115f5275ff4, 0x9a02736282284916, 0xec39f71196540e99, 0xf8b521b28dcc965a, 0x6af0b9d7f54c]) };
        // x((6,...)) = 6
        let x6 =  ProjectivePrimeFieldPoint{
            X: PrimeFieldElement{ A: Fp751Element([0xdba10, 0x0, 0x0, 0x0, 0x0, 0x3500000000000000, 0x3714fe4eb8399915, 0xc3a2584753eb43f4, 0xa3151d605c520428, 0xc116cf5232c7c978, 0x49a84d4b8efaf6aa, 0x305731e97514]) },
            Z: PrimeFieldElement::one(),
        };
        // y((6,...)) = oddsqrt(6^3 + 6)
        let y6 = PrimeFieldElement{ A: Fp751Element([0xe4786c67ba55ff3c, 0x6ffa02bcc2a148e0, 0xe1c5d019df326e2a, 0x232148910f712e87, 0x6ade324bee99c196, 0x4372f82c6bb821f3, 0x91a374a15d391ec4, 0x6e98998b110b7c75, 0x2e093f44d4eeb574, 0x33cdd14668840958, 0xb017cea89e353067, 0x6f907085d4b7]) };
        // Little-endian bytes of 3^239
        let three_239_bytes: [u8; 48] = [235, 142, 138, 135, 159, 84, 104, 201, 62, 110, 199, 124, 63, 161, 177, 89, 169, 109, 135, 190, 110, 125, 134, 233, 132, 128, 116, 37, 203, 69, 80, 43, 86, 104, 198, 173, 123, 249, 9, 41, 225, 192, 113, 31, 84, 93, 254, 6];
        // Little-endian bytes of 2^372
        let two_372_bytes: [u8; 47] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16];

        // E_0 : y^2 = x^3 + x has a = 0, so (a+2)/4 = 1/2
        let aPlus2Over4 = PrimeFieldElement{ A: Fp751Element([0x124d6, 0x0, 0x0, 0x0, 0x0, 0xb8e0000000000000, 0x9c8a2434c0aa7287, 0xa206996ca9a378a3, 0x6876280d41a41b52, 0xe903b49f175ce04f, 0xf8511860666d227, 0x4ea07cff6e7f]) };
        // Compute x(P_A) = x([3^239](11,...)) and x([3^239 + 1](11,...))
        let (xPA, xPAplus11) = ProjectivePrimeFieldPoint::scalar_mul_prime_field(&x11, &aPlus2Over4, &three_239_bytes[..]);
        // Compute x(P_B) = x([2^372](6,...)) and x([2^372 + 1](6,...))
        let (xPB, xPBplus6) = ProjectivePrimeFieldPoint::scalar_mul_prime_field(&x6, &aPlus2Over4, &two_372_bytes[..]);

        // Check that the computed x-coordinates are correct:
        let test_affine_xPA = xPA.to_affine();
        assert!(test_affine_xPA.vartime_eq(&AFFINE_X_PA), "Recomputed x(P_A) incorrectly: found\n{:?}\nexpected{:?}\n", AFFINE_X_PA, test_affine_xPA);

        let test_affine_xPB = xPB.to_affine();
        assert!(test_affine_xPB.vartime_eq(&AFFINE_X_PB), "Recomputed x(P_B) incorrectly: found\n{:?}\nexpected{:?}\n", AFFINE_X_PB, test_affine_xPB);

        // Recover y-coordinates and check that those are correct:
        let (mut X_A, mut Y_A, Z_A) = ProjectivePoint::okeya_sakurai_coordinate_recovery(&x11.X, &y11, &xPA, &xPAplus11);
        let invZ_A = Z_A.inv();
        Y_A = &Y_A * &invZ_A; // = Y_A / Z_A
        X_A = &X_A * &invZ_A; // = X_A / Z_A
        assert!(AFFINE_Y_PA.vartime_eq(&Y_A), "Recovered y(P_A) incorrectly: found\n{:?}\nexpected{:?}\n", Y_A, AFFINE_Y_PA);
        assert!(AFFINE_X_PA.vartime_eq(&X_A), "Recovered x(P_A) incorrectly: found\n{:?}\nexpected{:?}\n", X_A, AFFINE_X_PA);

        let (mut X_B, mut Y_B, Z_B) = ProjectivePoint::okeya_sakurai_coordinate_recovery(&x6.X, &y6, &xPB, &xPBplus6);
        let invZ_B = Z_B.inv();
        Y_B = &Y_B * &invZ_B; // = Y_B / Z_B
        X_B = &X_B * &invZ_B; // = X_B / Z_B
        assert!(AFFINE_Y_PB.vartime_eq(&Y_B), "Recovered y(P_B) incorrectly: found\n{:?}\nexpected{:?}\n", Y_B, AFFINE_Y_PB);
        assert!(AFFINE_X_PB.vartime_eq(&X_B), "Recovered x(P_B) incorrectly: found\n{:?}\nexpected{:?}\n", X_B, AFFINE_X_PB);
   }
}

//#[cfg(all(test, feature = "bench"))]
#[cfg(test)]
mod bench {
    use super::*;
    use test::Bencher;

    // A = 4385300808024233870220415655826946795549183378139271271040522089756750951667981765872679172832050962894122367066234419550072004266298327417513857609747116903999863022476533671840646615759860564818837299058134292387429068536219*i + 1408083354499944307008104531475821995920666351413327060806684084512082259107262519686546161682384352696826343970108773343853651664489352092568012759783386151707999371397181344707721407830640876552312524779901115054295865393760
    const CURVE_A: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0x8319eb18ca2c435e, 0x3a93beae72cd0267, 0x5e465e1f72fd5a84, 0x8617fa4150aa7272, 0x887da24799d62a13, 0xb079b31b3c7667fe, 0xc4661b150fa14f2e, 0xd4d2b2967bc6efd6, 0x854215a8b7239003, 0x61c5302ccba656c2, 0xf93194a27d6f97a2, 0x1ed9532bca75]),
                                                                  B: Fp751Element([0xb6f541040e8c7db6, 0x99403e7365342e15, 0x457e9cee7c29cced, 0x8ece72dc073b1d67, 0x6e73cef17ad28d28, 0x7aed836ca317472, 0x89e1de9454263b54, 0x745329277aa0071b, 0xf623dfc73bc86b9b, 0xb8e3c1d8a9245882, 0x6ad0b3d317770bec, 0x5b406e8d502b]) };

    // C = 933177602672972392833143808100058748100491911694554386487433154761658932801917030685312352302083870852688835968069519091048283111836766101703759957146191882367397129269726925521881467635358356591977198680477382414690421049768*i + 9088894745865170214288643088620446862479558967886622582768682946704447519087179261631044546285104919696820250567182021319063155067584445633834024992188567423889559216759336548208016316396859149888322907914724065641454773776307
    const CURVE_C: ExtensionFieldElement = ExtensionFieldElement{ A: Fp751Element([0x4fb2358bbf723107, 0x3a791521ac79e240, 0x283e24ef7c4c922f, 0xc89baa1205e33cc, 0x3031be81cff6fee1, 0xaf7a494a2f6a95c4, 0x248d251eaac83a1d, 0xc122fca1e2550c88, 0xbc0451b11b6cfd3d, 0x9c0a114ab046222c, 0x43b957b32f21f6ea, 0x5b9c87fa61de]),
                                                                  B: Fp751Element([0xacf142afaac15ec6, 0xfd1322a504a071d5, 0x56bb205e10f6c5c6, 0xe204d2849a97b9bd, 0x40b0122202fe7f2e, 0xecf72c6fafacf2cb, 0x45dfc681f869f60a, 0x11814c9aff4af66c, 0x9278b0c4eea54fe7, 0x9a633d5baf7f2e2e, 0x69a329e6f1a05112, 0x1d874ace23e4]) };
    
    const CURVE: ProjectiveCurveParameters = ProjectiveCurveParameters{ A: CURVE_A, C: CURVE_C };

    // Since function calls in constants and statics are limited to constant functions in Rust, we define it here and assign to other consts when needed.
    const EXTENSION_FIELD_ELEMENT_ONE: ExtensionFieldElement = ExtensionFieldElement {
            A: Fp751Element([0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2]),
            B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    };

    const THREE_POINT_LADDER_INPUTS: [ProjectivePoint; 3] = [
        // x(P)
        ProjectivePoint{
            X: ExtensionFieldElement{ A: Fp751Element([0xe8d05f30aac47247, 0x576ec00c55441de7, 0xbf1a8ec5fe558518, 0xd77cb17f77515881, 0x8e9852837ee73ec4, 0x8159634ad4f44a6b, 0x2e4eb5533a798c5, 0x9be8c4354d5bc849, 0xf47dc61806496b84, 0x25d0e130295120e0, 0xdbef54095f8139e3, 0x5a724f20862c]), 
                                      B: Fp751Element([0x3ca30d7623602e30, 0xfb281eddf45f07b7, 0xd2bf62d5901a45bc, 0xc67c9baf86306dd2, 0x4e2bd93093f538ca, 0xcfd92075c25b9cbe, 0xceafe9a3095bcbab, 0x7d928ad380c85414, 0x37c5f38b2afdc095, 0x75325899a7b779f4, 0xf130568249f20fdd, 0x178f264767d1]) },
            Z: EXTENSION_FIELD_ELEMENT_ONE,
        },
        // x(Q)
        ProjectivePoint{
            X: ExtensionFieldElement{ A: Fp751Element([0x2b71a2a93ad1e10e, 0xf0b9842a92cfb333, 0xae17373615a27f5c, 0x3039239f428330c4, 0xa0c4b735ed7dcf98, 0x6e359771ddf6af6a, 0xe986e4cac4584651, 0x8233a2b622d5518, 0xbfd67bf5f06b818b, 0xdffe38d0f5b966a6, 0xa86b36a3272ee00a, 0x193e2ea4f68f]), 
                                      B: Fp751Element([0x5a0f396459d9d998, 0x479f42250b1b7dda, 0x4016b57e2a15bf75, 0xc59f915203fa3749, 0xd5f90257399cf8da, 0x1fb2dadfd86dcef4, 0x600f20e6429021dc, 0x17e347d380c57581, 0xc1b0d5fa8fe3e440, 0xbcf035330ac20e8, 0x50c2eb5f6a4f03e6, 0x86b7c4571]) },
            Z: EXTENSION_FIELD_ELEMENT_ONE,
        },
        // x(P-Q)
        ProjectivePoint{
            X: ExtensionFieldElement{ A: Fp751Element([0x4aafa9f378f7b5ff, 0x1172a683aa8eee0, 0xea518d8cbec2c1de, 0xe191bcbb63674557, 0x97bc19637b259011, 0xdbeae5c9f4a2e454, 0x78f64d1b72a42f95, 0xe71cb4ea7e181e54, 0xe4169d4c48543994, 0x6198c2286a98730f, 0xd21d675bbab1afa5, 0x2e7269fce391]), 
                                      B: Fp751Element([0x23355783ce1d0450, 0x683164cf4ce3d93f, 0xae6d1c4d25970fd8, 0x7807007fb80b48cf, 0xa005a62ec2bbb8a2, 0x6b5649bd016004cb, 0xbb1a13fa1330176b, 0xbf38e51087660461, 0xe577fddc5dd7b930, 0x5f38116f56947cd3, 0x3124f30b98c36fde, 0x4ca9b6e6db37]) },
            Z: EXTENSION_FIELD_ELEMENT_ONE,
        },
    ];

    #[bench]
    fn point_addition(b: &mut Bencher) {
        let xP = ProjectivePoint{ X: CURVE_A, Z: CURVE_C };
        let mut xP2 = ProjectivePoint::new();
        let cached_params = CURVE.cached_params();
        xP2 = xP.double(&cached_params);

        b.iter(|| xP2.add(&xP, &xP));
    }

    #[bench]
    fn point_double(b: &mut Bencher) {
        let xP = ProjectivePoint{ X: CURVE_A, Z: CURVE_C };
        let cached_params = CURVE.cached_params();

        b.iter(|| xP.double(&cached_params));
    }

    #[bench]
    fn point_triple(b: &mut Bencher) {
        let xP = ProjectivePoint{ X: CURVE_A, Z: CURVE_C };
        let cached_params = CURVE.cached_triple_params();

        b.iter(|| xP.triple(&cached_params));
    }

    #[bench]
    fn scalar_mul_379bit_scalar(b: &mut Bencher) {
        //let xR = ProjectivePoint::new();
        let m_scalar_bytes: [u8; 48] = [84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4];
        
        b.iter(|| THREE_POINT_LADDER_INPUTS[0].scalar_mul(&CURVE, &m_scalar_bytes[..]));
    }

    #[bench]
    fn scalar_prime_field_mul_379bit_scalar(b: &mut Bencher) {
        let xR = ProjectivePrimeFieldPoint::new();
        let a24 = PrimeFieldElement::zero();
        let m_scalar_bytes: [u8; 48] = [84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4];
        
        b.iter(|| ProjectivePrimeFieldPoint::scalar_mul_prime_field(&xR, &a24, &m_scalar_bytes[..]));
    }

    #[bench]
    fn three_point_ladder_379bit_scalar(b: &mut Bencher) {
        //let xR = ProjectivePoint::new();
        let m_scalar_bytes: [u8; 48] = [84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4];
        
        b.iter(|| ProjectivePoint::three_point_ladder(&THREE_POINT_LADDER_INPUTS[0], &THREE_POINT_LADDER_INPUTS[1], &THREE_POINT_LADDER_INPUTS[2], &CURVE, &m_scalar_bytes[..]));
    }

    #[bench]
    fn right_to_left_ladder_379bit_scalar(b: &mut Bencher) {
        //let xR = ProjectivePoint::new();
        let m_scalar_bytes: [u8; 48] = [84, 222, 146, 63, 85, 18, 173, 162, 167, 38, 10, 8, 143, 176, 93, 228, 247, 128, 50, 128, 205, 42, 15, 137, 119, 67, 43, 3, 61, 91, 237, 24, 235, 12, 53, 96, 186, 164, 232, 223, 197, 224, 64, 109, 137, 63, 246, 4];
        
        b.iter(|| ProjectivePoint::right_to_left_ladder(&THREE_POINT_LADDER_INPUTS[0], &THREE_POINT_LADDER_INPUTS[1], &THREE_POINT_LADDER_INPUTS[2], &CURVE, &m_scalar_bytes[..]));
    }
}
