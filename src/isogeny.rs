use ::field::{Fp751Element, ExtensionFieldElement};
use ::curve::{ProjectiveCurveParameters, ProjectivePoint};

// Represents a 3-isogeny phi, holding the data necessary to evaluate phi.
#[derive(Copy, Clone)]
pub struct ThreeIsogeny {
    pub X: ExtensionFieldElement,
    pub Z: ExtensionFieldElement,
}

impl ThreeIsogeny {
    // Given a three-torsion point x3 = x(P_3) on the curve E_(A:C), construct the
    // three-isogeny phi : E_(A:C) -> E_(A:C)/<P_3> = E_(A':C').
    //
    // Returns a tuple (codomain, isogeny) = (E_(A':C'), phi).
    fn compute_three_isogeny(x3: &ProjectivePoint) -> (ProjectiveCurveParameters, ThreeIsogeny) {
        let isogeny = ThreeIsogeny{ X: x3.X, Z: x3.Z };
        // We want to compute
	    // (A':C') = (Z^4 + 18X^2Z^2 - 27X^4 : 4XZ^3)
	    // To do this, use the identity 18X^2Z^2 - 27X^4 = 9X^2(2Z^2 - 3X^2)
        let mut v1 = x3.X.square();      // = X^2
        let mut v0 = &(&v1 + &v1) + &v1; // = 3X^2
        v1 = &(&v0 + &v0) + &v0;         // = 9X^2
        let mut v2 = x3.Z.square();      // = Z^2
        let v3 = v2.square();            // = Z^4
        v2 = &v2 + &v2;                  // = 2Z^2
        v0 = &v2 - &v0;                  // = 2Z^2 - 3X^2
        v1 = &v1 * &v0;                  // = 9X^2(2Z^2 - 3X^2)
        v0 = &x3.X * &x3.Z;              // = XZ
        v0 = &v0 + &v0;                  // = 2XZ
        let a = &v3 + &v1;               // = Z^4 + 9X^2(2Z^2 - 3X^2)
        let c = &v0 * &v2;               // = 4XZ^3
        let codomain = ProjectiveCurveParameters{ A: a, C: c };

        (codomain, isogeny)
    }
    // Given a 3-isogeny phi and a point xP = x(P), compute x(Q), the x-coordinate
    // of the image Q = phi(P) of P under phi : E_(A:C) -> E_(A':C').
    //
    // The output xQ = x(Q) is then a point on the curve E_(A':C'); the curve
    // parameters are returned by the compute_three_isogeny function used to construct
    // phi.
    fn eval(&self, xP: &ProjectivePoint) -> ProjectivePoint {
        let phi = *self;
        let mut t0 = &phi.X * &xP.X; // = X3*XP
        let mut t1 = &phi.Z * &xP.Z; // = Z3*XP
        let mut t2 = &t0 - &t1;      // = X3*XP - Z3*ZP
        t0 = &phi.Z * &xP.X;         // = Z3*XP
        t1 = &phi.X * &xP.Z;         // = X3*ZP
        t0 = &t0 - &t1;              // = Z3*XP - X3*ZP
        t2 = t2.square();            // = (X3*XP - Z3*ZP)^2
        t0 = t0.square();            // = (Z3*XP - X3*ZP)^2
        let x = &t2 * &xP.X;         // = XP*(X3*XP - Z3*ZP)^2
        let z = &t0 * &xP.Z;         // = ZP*(Z3*XP - X3*ZP)^2
        let xQ = ProjectivePoint{ X: x, Z: z };

        xQ
    }
}

// Represents a 4-isogeny phi, holding the data necessary to evaluate phi.
//
// See compute_four_isogeny for more details.
#[derive(Copy, Clone)]
pub struct FourIsogeny {
    pub Xsq_plus_Zsq : ExtensionFieldElement,
    pub Xsq_minus_Zsq: ExtensionFieldElement,
    pub XZ2          : ExtensionFieldElement,
    pub Xpow4        : ExtensionFieldElement,
    pub Zpow4        : ExtensionFieldElement,
}

impl FourIsogeny {
    // Given a four-torsion point x4 = x(P_4) on the curve E_(A:C), compute the
    // coefficients of the codomain E_(A':C') of the four-isogeny phi : E_(A:C) ->
    // E_(A:C)/<P_4>.
    //
    // Returns a tuple (codomain, isogeny) = (E_(A':C') : phi).
    //
    // There are two sets of formulas in Costello-Longa-Naehrig for computing
    // four-isogenies. One set is for the case where (1,...) lies in the kernel of
    // the isogeny (this is the FirstFourIsogeny), and the other (this set) is for
    // the case that (1,...) is *not* in the kernel.
    fn compute_four_isogeny(x4: &ProjectivePoint) -> (ProjectiveCurveParameters, FourIsogeny) {
        let mut v0 = x4.X.square();    // = X4^2
        let v1 = x4.Z.square();        // = Z4^2
        let Xsq_plus_Zsq = &v0 + &v1;  // = X4^2 + Z4^2
        let Xsq_minus_Zsq = &v0 - &v1; // = X4^2 - Z4^2
        let mut XZ2 = &x4.X + &x4.Z;   // = X4 + Z4
        XZ2 = XZ2.square();            // = X4^2 + Z4^2 + 2X4Z4
        XZ2 = &XZ2 - &Xsq_plus_Zsq;    // = 2X4Z4
        let Xpow4 = v0.square();       // = X4^4
        let Zpow4 = v1.square();       // = Z4^4
        v0 = &Xpow4 + &Xpow4;          // = 2X4^4
        v0 = &v0 - &Zpow4;             // = 2X4^4 - Z4^4
        let a = &v0 + &v0;             // = 2(2X4^4 - Z4^4)
        let c = Zpow4;                 // = Z4^4

        let codomain = ProjectiveCurveParameters{ A: a, C: c };
        let isogeny = FourIsogeny{
            Xsq_plus_Zsq,
            Xsq_minus_Zsq,
            XZ2,
            Xpow4,
            Zpow4
        };

        (codomain, isogeny)
    }
    // Given a 4-isogeny phi and a point xP = x(P), compute x(Q), the x-coordinate
    // of the image Q = phi(P) of P under phi : E_(A:C) -> E_(A':C').
    //
    // The output xQ = x(Q) is then a point on the curve E_(A':C'); the curve
    // parameters are returned by the compute_four_isogeny function used to construct
    // phi.
    fn eval(&self, xP: &ProjectivePoint) -> ProjectivePoint {
        let phi = *self;
        // We want to compute formula (7) of Costello-Longa-Naehrig, namely
        //
        // Xprime = (2*X_4*Z*Z_4 - (X_4^2 + Z_4^2)*X)*(X*X_4 - Z*Z_4)^2*X
        // Zprime = (2*X*X_4*Z_4 - (X_4^2 + Z_4^2)*Z)*(X_4*Z - X*Z_4)^2*Z
        //
        // To do this we adapt the method in the MSR implementation, which computes
        //
        // X_Q = Xprime*( 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4 )
        // Z_Q = Zprime*( 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4 )
        //
        let mut t0 = &xP.X * &phi.XZ2;          // = 2*X*X_4*Z_4
        let mut t1 = &xP.Z * &phi.Xsq_plus_Zsq; // = (X_4^2 + Z_4^2)*Z
        t0 = &t0 - &t1;                         // = -X_4^2*Z + 2*X*X_4*Z_4 - Z*Z_4^2
        t1 = &xP.Z * &phi.Xsq_minus_Zsq;        // = (X_4^2 - Z_4^2)*Z
        let mut t2 = (&t0 - &t1).square();      // = 4*(X_4*Z - X*Z_4)^2*X_4^2
        t0 = &t0 * &t1;
        t0 = &t0 + &t0;
        t0 = &t0 + &t0;                         // = 4*(2*X*X_4*Z_4 - (X_4^2 + Z_4^2)*Z)*(X_4^2 - Z_4^2)*Z
        t1 = &t0 + &t2;                         // = 4*(X*X_4 - Z*Z_4)^2*Z_4^2
        t0 = &t0 * &t2;                         // = Zprime * 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2
        let z = &t0 * &phi.Zpow4;               // = Zprime * 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4
        t2 = &t2 * &phi.Zpow4;                  // = 4*(X_4*Z - X*Z_4)^2*X_4^2*Z_4^4
        t0 = &t1 * &phi.Xpow4;                  // = 4*(X*X_4 - Z*Z_4)^2*X_4^4*Z_4^2
        t0 = &t2 - &t0;                         // = -4*(X*X_4^2 - 2*X_4*Z*Z_4 + X*Z_4^2)*X*(X_4^2 - Z_4^2)*X_4^2*Z_4^2
        let x = &t1 * &t0;                      // = Xprime * 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4
        let xQ = ProjectivePoint{ X: x, Z: z };

        xQ
    }
}

// Represents a 4-isogeny phi. See compute_four_isogeny for details.
#[derive(Copy, Clone)]
pub struct FirstFourIsogeny {
    pub A: ExtensionFieldElement,
    pub C: ExtensionFieldElement,
}

impl FirstFourIsogeny {
    // Compute the "first" four-isogeny from the given curve. See also
    // compute_four_isogeny and Costello-Longa-Naehrig for more details.
    fn compute_first_four_isogeny(domain: &ProjectiveCurveParameters) -> (ProjectiveCurveParameters, FirstFourIsogeny) {
        let mut t0 = &domain.C + &domain.C; // = 2*C
        let c = &domain.A - &t0;            // = A - 2*C
        let mut t1 = &t0 + &t0;             // = 4*C
        t1 = &t1 + &t0;                     // = 6*C
        t0 = &t1 + &domain.A;               // = A + 6*C
        let a = &t0 + &t0;                  // = 2*(A + 6*C)
        
        let codomain = ProjectiveCurveParameters{ A: a, C: c };
        let isogeny = FirstFourIsogeny{ A: domain.A, C: domain.C };

        (codomain, isogeny)
    }
    // Given a 4-isogeny phi and a point xP = x(P), compute x(Q), the x-coordinate
    // of the image Q = phi(P) of P under phi : E_(A:C) -> E_(A':C').
    //
    // The output xQ = x(Q) is then a point on the curve E_(A':C'); the curve
    // parameters are returned by the compute_first_four_isogeny function used to 
    // construct phi.
        fn eval(&self, xP: &ProjectivePoint) -> ProjectivePoint {
        let phi = *self;
        let mut t0 = (&xP.X + &xP.Z).square(); // = (X+Z)^2
        let t2 = &xP.X * &xP.Z;                // = X*Z
        let mut t1 = &t2 + &t2;                // = 2*X*Z
        t1 = &t0 - &t1;                        // = X^2 + Z^2
        let mut x = &phi.A * &t2;              // = A*X*Z
        let t3 = &phi.C * &t1;                 // = C*(X^2 + Z^2)
        x = &x + &t3;                          // = A*X*Z + C*(X^2 + Z^2)
        x = &x * &t0;                          // = (X+Z)^2 * (A*X*Z + C*(X^2 + Z^2))
        t0 = (&xP.X - &xP.Z).square();         // = (X-Z)^2
        t0 = &t0 * &t2;                        // = X*Z*(X-Z)^2
        t1 = &phi.C + &phi.C;                  // = 2*C
        t1 = &t1 - &phi.A;                     // = 2*C - A
        let z = &t1 * &t0;                     // = (2*C - A)*X*Z*(X-Z)^2
        let xQ = ProjectivePoint{ X: x, Z: z };

        xQ
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Test the first four-isogeny from the base curve E_0(F_{p^2}).
    #[test]
    fn first_four_isogeny_versus_sage() {
        // sage: p = 2^372 * 3^239 - 1; Fp = GF(p)
        // sage: R.<x> = Fp[]
        // sage: Fp2 = Fp.extension(x^2 + 1, 'i')
        // sage: i = Fp2.gen()
        // sage: E0Fp = EllipticCurve(Fp, [0,0,0,1,0])
        // sage: E0Fp2 = EllipticCurve(Fp2, [0,0,0,1,0])
        // sage: x_PA = 11
        // sage: y_PA = -Fp(11^3 + 11).sqrt()
        // sage: x_PB = 6
        // sage: y_PB = -Fp(6^3 + 6).sqrt()
        // sage: P_A = 3^239 * E0Fp((x_PA,y_PA))
        // sage: P_B = 2^372 * E0Fp((x_PB,y_PB))
        // sage: def tau(P):
        // ....:     return E0Fp2( (-P.xy()[0], i*P.xy()[1]))
        // ....:
        // sage: m_B = 3*randint(0,3^238)
        // sage: m_A = 2*randint(0,2^371)
        // sage: R_A = E0Fp2(P_A) + m_A*tau(P_A)
        // sage: def y_recover(x, a):
        // ....:     return (x**3 + a*x**2 + x).sqrt()
        // ....:
        // sage: first_4_torsion_point = E0Fp2(1, y_recover(Fp2(1),0))
        // sage: sage_first_4_isogeny = E0Fp2.isogeny(first_4_torsion_point)
        // sage: a = Fp2(0)
        // sage: sage_isomorphism = sage_first_4_isogeny.codomain().isomorphism_to(EllipticCurve(Fp2, [0,(2*(a+6))/(a-2),0,1,0]))
        // sage: isogenized_R_A = sage_isomorphism(sage_first_4_isogeny(R_A))
        //
        let xR = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0xa179cb7e2a95fce9, 0xbfd6a0f3a0a892c0, 0x8b2f0aa4250ab3f3, 0x2e7aa4dd4118732d, 0x627969e493acbc2a, 0x21a5b852c7b8cc83, 0x26084278586324f2, 0x383be1aa5aa947c0, 0xc6558ecbb5c0183e, 0xf1f192086a52b035, 0x4c58b755b865c1b, 0x67b4ceea2d2c]), B: Fp751Element([0xfceb02a2797fecbf, 0x3fee9e1d21f95e99, 0xa1c4ce896024e166, 0xc09c024254517358, 0xf0255994b17b94e7, 0xa4834359b41ee894, 0x9487f7db7ebefbe, 0x3bbeeb34a0bf1f24, 0xfa7e5533514c6a05, 0x92b0328146450a9a, 0xfde71ca3fada4c06, 0x3610f995c2bd]) });
        let sage_isogenized_xR = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0xff99e76f78da1e05, 0xdaa36bd2bb8d97c4, 0xb4328cee0a409daf, 0xc28b099980c5da3f, 0xf2d7cd15cfebb852, 0x1935103dded6cdef, 0xade81528de1429c3, 0x6775b0fa90a64319, 0x25f89817ee52485d, 0x706e2d00848e697, 0xc4958ec4216d65c0, 0xc519681417f]), B: Fp751Element([0x742fe7dde60e1fb9, 0x801a3c78466a456b, 0xa9f945b786f48c35, 0x20ce89e1b144348f, 0xf633970b7776217e, 0x4c6077a9b38976e5, 0x34a513fc766c7825, 0xacccba359b9cd65, 0xd0ca8383f0fd0125, 0x77350437196287a, 0x9fe1ad7706d4ea21, 0x4d26129ee42d]) });

        let curve_params = ProjectiveCurveParameters{ A: ExtensionFieldElement::zero(), C: ExtensionFieldElement::one() };

        let (_, phi) = FirstFourIsogeny::compute_first_four_isogeny(&curve_params);
        let isogenized_xR = phi.eval(&xR);

        assert!(sage_isogenized_xR.vartime_eq(&isogenized_xR), "\nExpected\n{:?}\nfound\n{:?}", sage_isogenized_xR.to_affine(), isogenized_xR.to_affine());
    }

    #[test]
    fn four_isogeny_versus_sage() {
        // sage: p = 2^372 * 3^239 - 1; Fp = GF(p)
        //   ***   Warning: increasing stack size to 2000000.
        //   ***   Warning: increasing stack size to 4000000.
        // sage: R.<x> = Fp[]
        // sage: Fp2 = Fp.extension(x^2 + 1, 'i')
        // sage: i = Fp2.gen()
        // sage: E0Fp = EllipticCurve(Fp, [0,0,0,1,0])
        // sage: E0Fp2 = EllipticCurve(Fp2, [0,0,0,1,0])
        // sage: x_PA = 11
        // sage: y_PA = -Fp(11^3 + 11).sqrt()
        // sage: x_PB = 6
        // sage: y_PB = -Fp(6^3 + 6).sqrt()
        // sage: P_A = 3^239 * E0Fp((x_PA,y_PA))
        // sage: P_B = 2^372 * E0Fp((x_PB,y_PB))
        // sage: def tau(P):
        // ....:     return E0Fp2( (-P.xy()[0], i*P.xy()[1]))
        // ....:
        // sage: m_B = 3*randint(0,3^238)
        // sage: m_A = 2*randint(0,2^371)
        // sage: R_A = E0Fp2(P_A) + m_A*tau(P_A)
        // sage: def y_recover(x, a):
        // ....:     return (x**3 + a*x**2 + x).sqrt()
        // ....:
        // sage: first_4_torsion_point = E0Fp2(1, y_recover(Fp2(1),0))
        // sage: sage_first_4_isogeny = E0Fp2.isogeny(first_4_torsion_point)
        // sage: a = Fp2(0)
        // sage: E1A = EllipticCurve(Fp2, [0,(2*(a+6))/(a-2),0,1,0])
        // sage: sage_isomorphism = sage_first_4_isogeny.codomain().isomorphism_to(E1A)
        // sage: isogenized_R_A = sage_isomorphism(sage_first_4_isogeny(R_A))
        // sage: P_4 = (2**(372-4))*isogenized_R_A
        // sage: P_4._order = 4 #otherwise falls back to generic group methods for order
        // sage: X4, Z4 = P_4.xy()[0], 1
        // sage: phi4 = EllipticCurveIsogeny(E1A, P_4, None, 4)
        // sage: E2A_sage = phi4.codomain() # not in monty form
        // sage: Aprime, Cprime = 2*(2*X4^4 - Z4^4), Z4^4
        // sage: E2A = EllipticCurve(Fp2, [0,Aprime/Cprime,0,1,0])
        // sage: sage_iso = E2A_sage.isomorphism_to(E2A)
        // sage: isogenized2_R_A = sage_iso(phi4(isogenized_R_A))
        //
        let xR = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0xff99e76f78da1e05, 0xdaa36bd2bb8d97c4, 0xb4328cee0a409daf, 0xc28b099980c5da3f, 0xf2d7cd15cfebb852, 0x1935103dded6cdef, 0xade81528de1429c3, 0x6775b0fa90a64319, 0x25f89817ee52485d, 0x706e2d00848e697, 0xc4958ec4216d65c0, 0xc519681417f]), B: Fp751Element([0x742fe7dde60e1fb9, 0x801a3c78466a456b, 0xa9f945b786f48c35, 0x20ce89e1b144348f, 0xf633970b7776217e, 0x4c6077a9b38976e5, 0x34a513fc766c7825, 0xacccba359b9cd65, 0xd0ca8383f0fd0125, 0x77350437196287a, 0x9fe1ad7706d4ea21, 0x4d26129ee42d]) });
        let xP4 = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0x2afd75a913f3d5e7, 0x2918fba06f88c9ab, 0xa4ac4dc7cb526f05, 0x2d19e9391a607300, 0x7a79e2b34091b54, 0x3ad809dcb42f1792, 0xd46179328bd6402a, 0x1afa73541e2c4f3f, 0xf602d73ace9bdbd8, 0xd77ac58f6bab7004, 0x4689d97f6793b3b3, 0x4f26b00e42b7]), B: Fp751Element([0x6cdf918dafdcb890, 0x666f273cc29cfae2, 0xad00fcd31ba618e2, 0x5fbcf62bef2f6a33, 0xf408bb88318e5098, 0x84ab97849453d175, 0x501bbfcdcfb8e1ac, 0xf2370098e6b5542c, 0xc7dc73f5f0f6bd32, 0xdd76dcd86729d1cf, 0xca22c905029996e4, 0x5cf4a9373de3]) });
        let sage_isogenized_xR = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0x111efd8bd0b7a01e, 0x6ab75a4f3789ca9b, 0x939dbe518564cac4, 0xf9eeaba1601d0434, 0x8d41f8ba6edac998, 0xfcd2557efe9aa170, 0xb3c3549c098b7844, 0x52874fef6f81127c, 0xb2b9ac82aa518bb3, 0xee70820230520a86, 0xd4012b7f5efb184a, 0x573e4536329b]), B: Fp751Element([0xa99952281e932902, 0x569a89a571f2c7b1, 0x6150143846ba3f6b, 0x11fd204441e91430, 0x7f469bd55c9b07b, 0xb72db8b9de35b161, 0x455a9a37a940512a, 0xb0cff7670abaf906, 0x18c785b7583375fe, 0x603ab9ca403c9148, 0xab54ba3a6e6c62c1, 0x2726d7d57c4f]) });

        let (_, phi) = FourIsogeny::compute_four_isogeny(&xP4);
        let isogenized_xR = phi.eval(&xR);

        assert!(sage_isogenized_xR.vartime_eq(&isogenized_xR), "\nExpected\n{:?}\nfound\n{:?}", sage_isogenized_xR.to_affine(), isogenized_xR.to_affine());
    }

    #[test]
    fn three_isogeny_versus_sage() {
        // sage: %colors Linux
        // sage: p = 2^372 * 3^239 - 1; Fp = GF(p)
        //   ***   Warning: increasing stack size to 2000000.
        //   ***   Warning: increasing stack size to 4000000.
        // sage: R.<x> = Fp[]
        // sage: Fp2 = Fp.extension(x^2 + 1, 'i')
        // sage: i = Fp2.gen()
        // sage: E0Fp = EllipticCurve(Fp, [0,0,0,1,0])
        // sage: E0Fp2 = EllipticCurve(Fp2, [0,0,0,1,0])
        // sage: x_PA = 11
        // sage: y_PA = -Fp(11^3 + 11).sqrt()
        // sage: x_PB = 6
        // sage: y_PB = -Fp(6^3 + 6).sqrt()
        // sage: P_A = 3^239 * E0Fp((x_PA,y_PA))
        // sage: P_B = 2^372 * E0Fp((x_PB,y_PB))
        // sage: def tau(P):
        // ....:     return E0Fp2( (-P.xy()[0], i*P.xy()[1]))
        // ....:
        // sage: m_B = 3*randint(0,3^238)
        // sage: R_B = E0Fp2(P_B) + m_B*tau(P_B)
        // sage: P_3 = (3^238)*R_B
        // sage: def three_isog(P_3, P):
        // ....:     X3, Z3 = P_3.xy()[0], 1
        // ....:     XP, ZP = P.xy()[0], 1
        // ....:     x = (XP*(X3*XP - Z3*ZP)^2)/(ZP*(Z3*XP - X3*ZP)^2)
        // ....:     A3, C3 = (Z3^4 + 9*X3^2*(2*Z3^2 - 3*X3^2)), 4*X3*Z3^3
        // ....:     cod = EllipticCurve(Fp2, [0,A3/C3,0,1,0])
        // ....:     return cod.lift_x(x)
        // ....:
        // sage: isogenized_R_B = three_isog(P_3, R_B)
        //
        let xR = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0xbd0737ed5cc9a3d7, 0x45ae6d476517c101, 0x6f228e9e7364fdb2, 0xbba4871225b3dbd, 0x6299ccd2e5da1a07, 0x38488fe4af5f2d0e, 0xec23cae5a86e980c, 0x26c804ba3f1edffa, 0xfbbed81932df60e5, 0x7e00e9d182ae9187, 0xc7654abb66d05f4b, 0x262d0567237b]), B: Fp751Element([0x3a3b5b6ad0b2ac33, 0x246602b5179127d3, 0x502ae0e9ad65077d, 0x10a3a37237e1bf70, 0x4a1ab9294dd05610, 0xb0f3adac30fe1fa6, 0x341995267faf70cb, 0xa14dd94d39cf4ec1, 0xce4b7527d1bf5568, 0xe0410423ed45c7e4, 0x38011809b6425686, 0x28f52472ebed]) });
        let xP3 = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0x7bb7a4a07b0788dc, 0xdc36a3f6607b21b0, 0x4750e18ee74cf2f0, 0x464e319d0b7ab806, 0xc25aa44c04f758ff, 0x392e8521a46e0a68, 0xfc4e76b63eff37df, 0x1f3566d892e67dd8, 0xf8d2eb0f73295e65, 0x457b13ebc470bccb, 0xfda1cc9efef5be33, 0x5dbf3d92cc02]), B: Fp751Element([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]) });
        let sage_isogenized_xR = ProjectivePoint::from_affine(&ExtensionFieldElement{ A: Fp751Element([0x286db7d75913c5b1, 0xcb2049ad50189220, 0xccee90ef765fa9f4, 0x65e52ce2730e7d88, 0xa6b6b553bd0d06e7, 0xb561ecec14591590, 0x17b7a66d8c64d959, 0x77778cecbe1461e, 0x9405c9c0c41a57ce, 0x8f6b4847e8ca7d3d, 0xf625eb987b366937, 0x421b3590e345]), B: Fp751Element([0x566b893803e7d8d6, 0xe8c71a04d527e696, 0x5a1d8f87bf5eb51, 0x42ae08ae098724f, 0x4ee3d7c7af40ca2e, 0xd9f9ab9067bb10a7, 0xecd53d69edd6328c, 0xa581e9202dea107d, 0x8bcdfb6c8ecf9257, 0xe7cbbc2e5cbcf2af, 0x5f031a8701f0e53e, 0x18312d93e3cb]) });

        let (_, phi) = ThreeIsogeny::compute_three_isogeny(&xP3);
        let isogenized_xR = phi.eval(&xR);

        assert!(sage_isogenized_xR.vartime_eq(&isogenized_xR), "\nExpected\n{:?}\nfound\n{:?}", sage_isogenized_xR.to_affine(), isogenized_xR.to_affine());
    }
}
