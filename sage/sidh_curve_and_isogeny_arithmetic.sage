# Import Sage and other SIDH related modules
from sage.all import *
from sidh_parameters import *
from sidh_field_arithmetic import *

"""
    This file contains all the elliptic curve and isogeny arithmetic for the
    original SIDH key exchange as well as additional functions for public-key
    compression such as deterministic torsion basis generation. 
"""

# Turn off arithmetic proof
proof.arithmetic(False)

# Arithmetic functions
def j_inv(A, C):
    """
        Computes the j-invariant of a Montgomery curve with projective constant.

        Input:  
        - The projective curve constant (A:C) given by A,C in Fp2.

        Output: 
        - The j-invariant j=256*(A^2-3*C^2)^3/(C^4*(A^2-4*C^2)) of the Montgomery 
          curve B*y^2=x^3+(A/C)*x^2+x or (equivalently) the j-invariant of 
          B'*y^2=C*x^3+A*x^2+C*x.
    """
    
    jinv = A^2
    t1 = C^2
    t0 = t1 + t1
    t0 = jinv - t0
    t0 = t0 - t1
    jinv = t0 - t1
    t1 = t1^2
    jinv = jinv * t1
    t0 = t0 + t0
    t0 = t0 + t0
    t1 = t0^2
    t0 = t0 * t1
    t0 = t0 + t0
    t0 = t0 + t0
    jinv = 1 / jinv
    jinv = t0 * jinv
    
    return jinv # Total: 3M+4S+8a+1I

def xDBLADD(XP, ZP, XQ, ZQ, xPQ, A24):
    """
        Carries out a typical step in the Montgomery ladder: a simultaneous 
        doubling and differential addition.

        Input: 
        - The projective Montgomery x-coordinates of xP=XP/ZP and xQ=XQ/ZQ, 
        - the affine difference x(P-Q) and 
        - the Montgomery curve constant A24=(A+2)/4.

        Output: 
        - The projective Montgomery x-coordinates of x(2P)=X2P/Z2P and
          x(Q+P)=XQP/ZQP.
    """
    
    t0 = XP + ZP
    t1 = XP - ZP
    X2P = t0^2
    t2 = XQ - ZQ
    XQP = XQ + ZQ
    t0 = t0 * t2
    Z2P = t1^2
    t1 = t1 * XQP
    t2 = X2P - Z2P
    X2P = X2P * Z2P
    XQP = A24 * t2
    ZQP = t0 - t1
    Z2P = XQP + Z2P
    XQP = t0 + t1
    Z2P = Z2P * t2
    ZQP = ZQP^2
    XQP = XQP^2
    ZQP = xPQ * ZQP
    
    return X2P, Z2P, XQP, ZQP # Total: 6M+4S+8a

def xADD(XP, ZP, XQ, ZQ, xPQ):
    """
        Computes a standard Montgomery differential addition.

        Input: 
        - The projective Montgomery x-coordinates of xP=XP/ZP and xQ=XQ/ZQ, 
        - and the affine difference x(P-Q).

        Output: 
        - The projective Montgomery x-coordinates of x(Q+P)=XQP/ZQP.
    """
    
    t0 = XP + ZP
    t1 = XP - ZP
    XP = XQ - ZQ
    ZP = XQ + ZQ
    t0 = XP * t0
    t1 = ZP * t1
    ZP = t0 - t1
    XP = t0 + t1
    ZP = ZP^2
    XQP = XP^2
    ZQP = xPQ * ZP
    
    return XQP, ZQP # Total: 3M+2S+6a

def xDBL(X, Z, A24, C24):
    """
        This is NOT the stereotypical Montgomery x-only doubling, since it assumes 
        that the curve constant is projective.  

        Input: 
        - The projective Montgomery x-coordinates of xP=XP/ZP and 
        - the Montgomery curve constant A24/C24 = (A/C+2)/4.

        Output: 
        - The projective Montgomery x-coordinates of x(2P)=X2P/Z2P.
    """
    
    t0 = X - Z
    t1 = X + Z
    t0 = t0^2
    t1 = t1^2
    Z2 = C24 * t0
    X2 = Z2 * t1
    t1 = t1 - t0
    t0 = A24 * t1
    Z2 = Z2 + t0
    Z2 = Z2 * t1
    
    return X2, Z2 # Total: 4M+2S+4a

def xDBLe(XP, ZP, A, C, e):
    """
        This just computes [2^e](X:Z) on the Montgomery curve with projective 
        constant (A:C) via 2^e repeated doublings.

        Input: 
        - The projective Montgomery x-coordinates of xP=XP/ZP and 
        - the Montgomery curve constant A/C.

        Output: 
        - The projective Montgomery x-coordinates of x(2^e*P)=XeP/ZeP.
    """
    
    A24num = C + C
    A24den = A24num + A24num
    A24num = A24num + A
    
    XeP, ZeP = XP, ZP
    
    for i in [1..e]:
        XeP, ZeP = xDBL(XeP, ZeP, A24num, A24den)
        
    return XeP, ZeP

def xDBL_basefield(X, Z, A24, C24):
    """
        This is NOT the stereotypical Montgomery x-only doubling, since it assumes 
        that the curve constant is projective. All computations are over the base 
        field.

        Input: 
        - The projective Montgomery x-coordinates of xP=XP/ZP and 
        - the Montgomery curve constant A24/C24:=(A/C+2)/4.

        Output: 
        - The projective Montgomery x-coordinates of x(2P)=X2P/Z2P.
    """
    
    # NOTE: This function assumes that A24=1, C24=2 are fixed
    assert A24 == 1
    assert C24 == 2
    
    t0 = X - Z
    t1 = X + Z
    t0 = t0^2
    t1 = t1^2
    Z2 = t0 + t0
    X2 = Z2 * t1
    t1 = t1 - t0
    Z2 = Z2 + t1
    Z2 = Z2 * t1
    
    return X2, Z2 # Total: 2M+2S+5a

def xDBLADD_basefield(XP, ZP, XQ, ZQ, xPQ, A24, C24):
    """
        This function carries out a typical step in the Montgomery ladder: 
        simultaneous doubling and differential addition. All computations are over 
        the base field.

        Input: 
        - The projective Montgomery x-coordinates of xP=XP/ZP and xQ=XQ/ZQ, 
        - the affine difference x(P-Q) and 
        - the Montgomery curve constant A24=(A+2)/4.

        Output: 
        - The projective Montgomery x-coordinates of x(2P)=X2P/Z2P and
          x(Q+P)=XQP/ZQP.
    """
    
    # NOTE: This function assumes that A24=1, C24=2 are fixed
    assert A24 == 1
    assert C24 == 2
    
    t0 = XP + ZP
    t1 = XP - ZP
    X2P = t0^2
    t2 = XQ - ZQ
    XQP = XQ + ZQ
    t0 = t0 * t2
    Z2P = t1^2
    t1 = t1 * XQP
    t2 = X2P - Z2P
    Z2P = Z2P + Z2P
    X2P = X2P * Z2P
    Z2P = t2 + Z2P
    ZQP = t0 - t1
    XQP = t0 + t1
    Z2P = Z2P * t2
    ZQP = ZQP^2
    XQP = XQP^2
    ZQP = xPQ * ZQP
    
    return X2P, Z2P, XQP, ZQP # Total: 5M+4S+9a

def ADD_formula(X1, Y1, Z1, x2, y2, z2, A):
    v0 = (x2*Z1+X1*z2)*(x2*X1+Z1*z2)+2*Z1*z2*(A*x2*X1-y2*Y1)
    X3 = v0*(-x2*Z1*X1*z2)
    Y3 = (X1*z2+x2*Z1)*(y2*z2*(X1^2+Z1^2)-Z1*Y1*(z2^2+x2^2))+2*Z1*z2*(y2*X1-x2*Y1)*(A*(X1*z2+x2*Z1)+x2*X1+Z1*z2)
    Z3 = (-x2*Z1+X1*z2)^3
    
    return X3, Y3, Z3

def ADD(X1, Y1, Z1, x2, y2, z2, A):
    # Addition on a Montgomery curve
    # Cost: 20*M + 5*S + 9*Add + 4*Sub
    t0 = x2 * Z1
    t1 = X1 * z2
    t2 = t0 + t1
    t3 = t1 - t0
    t0 = x2 * X1
    t1 = Z1 * z2
    t4 = t0 + t1
    t0 = t0 * A
    t5 = y2 * Y1
    t0 = t0 - t5
    t0 = t0 * t1
    t0 = t0 + t0
    t5 = t2 * t4
    t5 = t5 + t0
    t0 = X1^2
    t6 = Z1^2
    t0 = t0 + t6
    t1 = t1 + t1
    t7 = y2 * X1
    t6 = x2 * Y1
    t7 = t7 - t6
    t1 = t1 * t7
    t7 = A * t2
    t4 = t4 + t7
    t4 = t1 * t4
    t1 = y2 * z2
    t0 = t0 * t1
    t1 = z2^2
    t6 = x2^2
    t1 = t1 + t6
    t6 = Z1 * Y1
    t1 = t1 * t6
    t0 = t0 - t1
    t0 = t2 * t0
    X3 = t5 * t3
    Y3 = t4 + t0
    t0 = t3^2
    Z3 = t3 * t0
    
    return X3, Y3, Z3

def LADDER(x, m, A24, C24, AliceOrBob):
    """
        The legendary Montgomery ladder.

        Input: 
        - The affine x-coordinate of a point on E: B*y^2=x^3+A*x^2+x, 
        - a scalar m, and 
        - the curve constant (A+2)/4.

        Output:
        - The projective x-coordinates of x(mP)=X0/Z0 and x((m+1)P)=X1/Z1. 
    """
    
    bits = m.digits(base=2)
    
    # NOTE: This function assumes that A24=1, C24=2 are fixed
    A24, C24 = 1, 2 
    X0, Z0 = 1, 0   # Initializing with the point at infinity and (x,1)
    X1, Z1 = x, 1
    
    if (AliceOrBob == Alice):
        nbits = eAbits
    else:
        nbits = eBbits
        
    for i in [1..(nbits-len(bits))]:
        X0, Z0, X1, Z1 = xDBLADD_basefield(X0, Z0, X1, Z1, x, A24, C24)
    
    for i in range(len(bits)-1, -1, -1):
        if bits[i] == 0:
            X0, Z0, X1, Z1 = xDBLADD_basefield(X0, Z0, X1, Z1, x, A24, C24)
        else:
            X1, Z1, X0, Z0 = xDBLADD_basefield(X1, Z1, X0, Z0, x, A24, C24)
    
    return X0, Z0, X1, Z1

def mont_ladder(x, m, A24):
    """
        Similar to function in above (but different), doesn't need to be 
        constant time.
        The legendary Montgomery ladder.

        Input: 
        - The affine x-coordinate of a point on E: B*y^2=x^3+A*x^2+x, 
        - a scalar m, and 
        - the curve constant (A+2)/4.

        Output:
        - The projective x-coordinates of x(mP)=X0/Z0 and x((m+1)P)=X1/Z1. 
    """
    bits = m.digits(base=2)
    X0, Z0 = 1, 0   # Initializing with the point at infinity and (x,1)
    X1, Z1 = x, 1

    for i in range(len(bits)-1, -1, -1):
        if bits[i] == 0:
            X0, Z0, X1, Z1 = xDBLADD(X0, Z0, X1, Z1, x, A24)
        else:
            X1, Z1, X0, Z0 = xDBLADD(X1, Z1, X0, Z0, x, A24)

    return X0, Z0, X1, Z1

def secret_pt(x, y, m, AliceOrBob):
    """
        Computes key generation ***entirely in the base field*** by exploiting a 
        1-dimensional Montgomery ladder in the trace zero subgroup and recovering 
        the y-coordinate for the addition. All operations below are in the base 
        field Fp.

        Input: 
        - A point P=(x,y) on E in the base field subgroup,
        - the point Q=(-x,y*i) on E in the trace-zero subgroup, and
        - the scalar m.

        Output: 
        - Field elements RX0,RX1,RZ in Fp such that (RX0+RX1*i)/RZ is the 
          x-coordinate of P+[m]Q. 
    """
    
    # NOTE: This function assumes that A24=1, C24=2 are fixed
    A24, C24 = 1, 2
    X0, Z0, X1, Z1 = LADDER(-x, m, A24, C24, AliceOrBob)
    
    RZ = x * Z0
    RX0 = X0 * x
    t4 = X0 + RZ
    RZ = X0 - RZ
    t0 = t4^2
    RX0 = Z0 - RX0
    t0 = t0 * X1
    RX0 = RX0 * RZ
    t2 = y * Z1
    t1 = y * Z0
    t2 = t2 + t2
    RX1 = t2 * Z0
    RX0 = RX0 * Z1
    RX0 = RX0 - t0
    t1 = t1 * RX1
    t0 = RX1^2
    t2 = t2 * RX1
    RX1 = t1 * RX0
    t3 = t1 + RX0
    RX1 = RX1 + RX1
    t1 = t1 - RX0
    t1 = t1 * t3
    RZ = RZ^2
    t2 = t2 * t4
    t2 = t2 * RZ
    RZ = t0 * RZ
    RX0 = t1 - t2
    
    return RX0, RX1, RZ # Total: 15M+3S+9a 

def LADDER_3_pt(m, xP, xQ, xPQ, A, AliceOrBob):
    """
        This is Algorithm 1 of De Feo, Jao and Plut. It computes P+[m]Q via x-only 
        arithmetic.

        Input: 
        - The three affine points xP,xQ,xPQ (they are affine as they are compressed 
          before transmission over the wire) and 
        - the Montgomery constant A.

        Output: 
        - The projective Montgomery x-coordinates of x(P+[m]Q)=WX/WZ.
    """
    
    bits = m.digits(base=2)
    
    A24num = A + 2 # Tailored for the special xDBL function
    A24 = A24num / 2
    A24 = A24 / 2
    
    UX, UZ = 1, 0  # Initializing with point at infinity (1:0).
    VX, VZ = xQ, 1 # (xQ:1)
    WX, WZ = xP, 1 # (xP:1)
    
    if AliceOrBob == Alice:
        nbits = eAbits
    else:
        nbits = eBbits
    
    for i in [1..(nbits-len(bits))]:
        WX, WZ = xADD(UX, UZ, WX, WZ, xP)
        UX, UZ, VX, VZ = xDBLADD(UX, UZ, VX, VZ, xQ, A24)
    
    for i in range(len(bits)-1, -1, -1):
        if bits[i] == 0:
            WX, WZ = xADD(UX, UZ, WX, WZ, xP)
            UX, UZ, VX, VZ = xDBLADD(UX, UZ, VX, VZ, xQ, A24)
        else:
            UX, UZ = xADD(UX, UZ, VX, VZ, xQ)
            VX, VZ, WX, WZ = xDBLADD(VX, VZ, WX, WZ, xPQ, A24)
    
    return WX, WZ

def get_4_isog(X4, Z4):
    """
        Given a projective point (X4:Z4) of order 4 on a Montgomery curve, this 
        computes the corresponding 4-isogeny.

        Input: 
        - The projective point of order four (X4:Z4).

        Output: 
        - The 4-isogenous Montgomery curve with projective coefficient A/C and 
          the 5 coefficients that are used to evaluate the isogeny at a point 
          (see the next function).
    """
    
    coeff0 = X4 + Z4
    coeff3 = X4^2
    coeff4 = Z4^2
    coeff0 = coeff0^2
    coeff1 = coeff3 + coeff4
    coeff2 = coeff3 - coeff4
    coeff3 = coeff3^2
    coeff4 = coeff4^2
    A = coeff3 + coeff3
    coeff0 = coeff0 - coeff1
    A = A - coeff4
    C = coeff4
    A = A + A  # Total: 5S+7a
    
    return A, C, [coeff0, coeff1, coeff2, coeff3, coeff4]

def eval_4_isog(coeff, X, Z):
    """
        Given a 4-isogeny phi defined by the 5 coefficients in coeff (computed in 
        the function get_4_isog), evaluates the isogeny at the point (X:Z) in the 
        domain of the isogeny.

        Input: 
        - The coefficients defining the isogeny, and 
        - the projective point P=(X:Z).

        Output: 
        - The projective point phi(P)=(X:Z) in the codomain. Variables are 
          overwritten because they replace inputs in the routine.
    """
    
    X = coeff[0] * X
    t0 = coeff[1] * Z
    X = X - t0
    Z = coeff[2] * Z
    t0 = X - Z
    Z = X * Z
    t0 = t0^2
    Z = Z + Z
    Z = Z + Z
    X = t0 + Z
    Z = t0 * Z
    Z = coeff[4] * Z
    t0 = t0 * coeff[4]
    t1 = X * coeff[3]
    t0 = t0 - t1
    X = X * t0  # Total: 9M+1S+6a
    
    return X, Z

def first_4_isog(X4, Z4, A):
    """
        This is the very first 4-isogeny computed by Alice, which is different
        from all subsequent 4-isogenies because the point (1,..) is already in the 
        kernel, so it doesn't need composition with the preliminary isomorphism.
        (See De Feo, Jao and Plut, Section 4.3).

        Input: 
        - The projective point (X4:Z4) and 
        - the curve constant A (that is affine because it is passed over the wire 
          or a fixed system parameter).

        Output: 
        - The projective point (X4:Z4) in the codomain and
        - the isogenous curve constant A/C. Variables are overwritten because they 
          replace inputs in the routine.
    """
    
    t0 = X4^2
    X = Z4^2
    Z = X4 * Z4
    X4 = A * Z
    Z = Z + Z
    Z4 = Z - X4
    t0 = t0 + X
    X = t0 + Z
    Z = t0 - Z
    X4 = X4 + t0
    X = X * X4
    Z = Z4 * Z
    C = A - 2
    A = A + 6
    A = A + A
    
    return X, Z, A, C # Total: 4M+2S+9a

def xTPL(X, Z, A24, C24):
    """
        This is NOT the stereotypical Montgomery x-only tripling, since it assumes 
        that the curve constant is projective.  

        Input: 
        - The projective Montgomery x-coordinates of xP=X/Z and 
        - the Montgomery curve constant A/C

        Output: 
        - The projective Montgomery x-coordinates of x(3P)=X3/Z3.
    """
    
    t2 = X - Z
    t3 = X + Z
    t0 = t2^2
    t1 = t3^2
    t4 = C24 * t0
    t5 = t4 * t1
    t1 = t1 - t0
    t0 = A24 * t1
    t4 = t4 + t0
    t4 = t4 * t1
    t0 = t5 + t4
    t1 = t5 - t4
    t0 = t2 * t0
    t1 = t3 * t1
    t4 = t0 - t1
    t5 = t0 + t1
    t4 = t4^2
    t5 = t5^2
    t4 = X * t4
    X3 = Z * t5
    Z3 = t4
    
    return X3, Z3 # Total: 8M+4S+8a

def xTPLe(X, Z, A, C, e):
    """
        This function just computes [3^e](X:Z) on a Montgomery curve with 
        projective constant via 3^e repeated triplings.  

        Input: 
        - The projective Montgomery x-coordinates of xP=X/Z and 
        - the Montgomery curve constant A/C.

        Output: 
        - The projective Montgomery x-coordinates of x(eP)=XeP/ZeP.
    """
    
    XeP, ZeP = X, Z
    A24 = A + 2*C
    C24 = 4*C
    
    for i in [1..e]:
        XeP, ZeP = xTPL(XeP, ZeP, A24, C24)
    
    return XeP, ZeP

def get_3_isog(X3, Z3):
    """
        Given a projective point (X3:Z3) of order 3 on a Montgomery curve, this 
        computes the corresponding 3-isogenous curve.

        Input: 
        - The projective point of order three (X3:Z3).

        Output: 
        - The 3-isogenous Montgomery curve with projective coefficient A/C. 
          No coefficients are computed for the evaluation phase as all operations 
          in the evaluation depend on the input point to the isogeny.
    """
    
    t0 = X3^2
    t1 = t0 + t0
    t0 = t0 + t1
    t1 = Z3^2
    A = t1^2
    t1 = t1 + t1
    C = t1 + t1
    t1 = t0 - t1
    t1 = t1 * t0
    A = A - t1
    A = A - t1
    A = A - t1
    t1 = X3 * Z3
    C = C * t1
    
    return A, C # Total: 3M+3S+8a

def eval_3_isog(X3, Z3, X, Z):
    """
        Given a projective point (X3:Z3) of order 3 on a Montgomery curve and a 
        projective point x(P)=(X:Z), this function evaluates the corresponding 
        3-isogeny at x(P): phi(X:Z).

        Input:
        - The projective point (X3:Z3) of order three,
        - the projective Montgomery x-coordinates of x(P)=X/Z.

        Output: 
        - The projective Montgomery x-coordinates of the evaluation of phi at
          (X:Z).
    """
    
    t0 = X3 * X
    t1 = Z3 * X
    t2 = Z3 * Z
    t0 = t0 - t2
    t2 = Z * X3
    t1 = t1 - t2
    t0 = t0^2
    t1 = t1^2
    X = X * t0
    Z = Z * t1
    
    return X, Z # Total: 6M+2S+2a

def inv_3_way(z1, z2, z3):
    """
        This function computes inverses of three elements by sharing the inversions
        via Montgomery's simultaneous inversion trick.

        Input: 
        - The three values to be inverted: z1,z2,z3,z4.

        Output: 
        - Their inverses 1/z1,1/z2,1/z3 (over-ride variables).
    """
    
    t0 = z1 * z2
    t1 = t0 * z3
    t1 = 1 / t1
    t2 = z3 * t1
    t3 = t2 * z2
    z2 = t2 * z1
    z3 = t0 * t1
    z1 = t3
    
    return z1, z2, z3 # Total: 6M+1I

def distort_and_diff(xP):
    """
        Given the x-coordinate of an affine point P, this function returns the
        projective x-coordinates of the difference point Q-P, where Q=tau(P) is 
        the image under the distortion map of the point P. 

        Input: 
        - The coordinate xP of the point P=(xP,yP).

        Output: 
        - The point (x(Q-P),z(Q-P)), where Q=tau(P).
    """
    
    XD = xP^2
    XD = XD + 1
    XD = XD * j
    ZD = xP + xP
    
    return XD, ZD

def get_A(xP, xQ, xR):
    """
        Given the x-coordinates of P, Q, and R, returns the value A 
        (corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x) 
        such that R=Q-P on E_A

        Input: 
        - The x-coordinates xP, xQ, and xR of the points P, Q and R

        Output: 
        - The coefficient A corresponding to the curve E_A: y^2=x^3+A*x^2+x
    """
    
    t1 = xP + xQ
    t0 = xP * xQ
    A = xR * t1
    A = A + t0
    t0 = t0 * xR
    A = A - 1
    t0 = t0 + t0
    t1 = t1 + xR
    t0 = t0 + t0
    A = A^2
    t0 = 1 / t0
    A = A * t0
    A = A - t1  # Total: 4M+1S+7a+1I
    
    return A

# This is merely elligator 2 for X
def get_X_on_curve(r, A0, A1):
    # All Fp arithmetic
    r1 = list[2*r-2]
    r0 = list[2*r-1]
    rsq = r^2
    t0 = A1 * r1
    v0 = A0 * r0
    v0 = v0 - t0
    t0 = A1 * r0
    v1 = A0 * r1
    v1 = v1 + t0
    t0 = v0 + A0
    t1 = v1 + A1
    t2 = v0 * v1
    t2 = t2 + t2
    a = t2 * A1
    a = v0 - a
    b = t2 * A0
    b = b + v1
    t2 = v0 + v0
    t2 = t2 + t0
    t3 = v0^2
    t0 = t0 * t3
    a = a + t0
    t0 = v1^2
    t2 = t0 * t2
    a = a - t2
    t0 = t0 * t1
    b = b - t0
    t1 = t1 + v1
    t1 = t1 + v1
    t1 = t1 * t3
    b = t1 + b
    t0 = a^2
    t1 = b^2
    t0 = t0 + t1
    t1 = t0^((p + 1) / 4) 
    t2 = t1^2
    
    if t2 != t0:
        x0 = v0 + v0
        x0 = x0 + x0
        x0 = x0 - v1
        x0 = rsq * x0
        x1 = v1 + v1
        x1 = x1 + x1
        x1 = x1 + v0
        x1 = rsq * x1
        t0 = a
        a = a + a
        a = a + a
        a = a - b
        a = rsq * a
        b = b + b
        b = b + b
        b = b + t0
        b = rsq * b
        t1 = t1 * rsq
        t1 = t1 * sqrt17
    else:
        x0 = v0
        x1 = v1
    
    return x0, x1, t1, a, b # Still not parsed back to Fp2
                            # t1,a optional out if calld by "get_pt_on_curve"
    
# This is merely elligator 2
def get_pt_on_curve(r, A0, A1):
    # All Fp arithmetic
    x0, x1, t1, a, b = get_X_on_curve(r, A0, A1)
    
    t0 = a + t1
    t0 = t0 / 2
    t1 = t0^((p - 3) / 4)
    t3 = t0 * t1
    t2 = t3^2
    t1 = t1 / 2
    t1 = t1 * b
    
    if t2 == 0:
        y0 = t3
        y1 = t1
    else:
        y1 = -t3
        y0 = t1
    
    return x0, x1, y0, y1 # Still not parsed back to Fp2

def get_point_notin_2E(alpha, A0, A1):
    """
        input is alpha, a small integer (parsed in Fp)
        input also A0,A1 such that A=A0+A1*i is Montgomery coefficient
        output is alpha such that alpha*u is a good x-coordinate
    """
    
    # All Fp arithmetic.
    x0 = A0 - A1
    x0 = x0 + A0
    x0 = 8 * x0
    X0 = x0 - A0
    x1 = A0 + A1
    x1 = x1 + A1
    x1 = 8 * x1
    X1 = x1 - A1
    
    while True:
        alpha += 1
        t0 = 52 * alpha
        x0 = X0 + t0
        t0 = 47 * alpha
        x1 = X1 + t0
        x0 = x0 * alpha
        x0 = x0 + 4
        x1 = x1 * alpha
        x1 = x1 + 1
        x0 = x0^2
        x1 = x1^2
        t0 = alpha^2
        x0 = x0 + x1
        t0 = t0 * x0
        sqrt = t0^((p + 1) / 2) # 371 sqrs, 239 cubes

        if sqrt == t0:
            break
    
    return alpha # alpha*u == alpha*(i+4) is good x-coordinate

def generate_2_torsion_basis(A):
    """
        Main function that calls the above functions.
        The function takes curve constant A as input
        and outputs R1=(X1:Y1:Z1) and R2=(X2:Y2:Z2), a basis for E[2^372]
    """
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "v" to polynomial, and get the coefficients
    P = A.polynomial()
    real, imag = P.coefficients(sparse=False)

    A0 = Fp(real)
    A1 = Fp(imag)
    
    alpha = 0
    alpha = get_point_notin_2E(alpha, A0, A1) # Arithmetic inside here is in Fp.
    
    X1 = alpha*j + alpha*4 # Parse alpha in Fp into Fp2 x-coordinate
    X1, Z1 = xTPLe(X1, 1, A, 1, 239) # xTPL assumes projective constant, but this is minor
    XP, ZP = xDBLe(X1, Z1, A, 1, 371)
    
    while True:
        # This loop is necessary to ensure that the order of the WeilPairing is oA
        # and not smaller. This ensures that we have a basis.
        alpha = get_point_notin_2E(alpha, A0, A1)
        X2 = alpha*j + alpha*4
        X2, Z2 = xTPLe(X2, 1, A, 1, 239)
        
        XQ, ZQ = xDBLe(X2, Z2, A, 1, 371)
        t0 = XP * ZQ
        t1 = XQ * ZP
        t0 = t0 - t1

        if t0 != 0:
            break
    
    # All below is in Fp2
    t0 = Z1^2
    Y1 = A * Z1
    Y1 = X1 + Y1
    Y1 = Y1 * X1
    Y1 = Y1 + t0
    Y1 = Y1 * X1
    t0 = t0 * Z1
    
    t1 = sqrt_fp2_frac(Y1, t0)
    t0 = Z2^2
    Y2 = A * Z2
    Y2 = X2 + Y2
    Y2 = Y2 * X2
    Y2 = Y2 + t0
    Y2 = Y2 * X2
    t0 = t0 * Z2
    Y1 = t1 * Z1
    t1 = sqrt_fp2_frac(Y2, t0)
    Y2 = t1 * Z2
    
    return X1, Y1, Z1, X2, Y2, Z2

def get_3_torsion_elt(A, r):
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "A" to polynomial, and get the coefficients
    P = A.polynomial()
    real, imag = P.coefficients(sparse=False)

    A0 = real
    A1 = imag

    x0, x1, _, _, _ = get_X_on_curve(r, A0, A1)
    X = x0 + x1*j # Parse into Fp2
    X, Z = xDBLe(X, 1, A, 1, 372)
    XX, ZZ = X, Z
    
    A24, C24 = A+2, 4
    
    triples = 0
    while ZZ != 0:
        X3, Z3 = XX, ZZ
        XX, ZZ = xTPL(XX, ZZ, A+2, 4)
        triples += 1
    
    return X3, Z3, X, Z, triples

def generate_3_torsion_basis(A):
    # Except for the function called within, most of the arithmetic is in Fp2
    r = 1
    X3, Z3, X, Z, triples = get_3_torsion_elt(A, r)

    if triples == 239:
        pts_found = 1
        X1, Z1 = X, Z
        u = A * Z1
        u = u + X1
        u = u * X1
        v = Z1^2
        u = u + v
        u = u * X1
        v = v * Z1
        Y1 = sqrt_fp2_frac(u, v)
        Y1 = Y1 * Z1
    else:
        pts_found = 0
    
    u = A * Z3
    u = u + X3
    u = u * X3
    v = Z3^2
    u = u + v
    u = u * X3
    v = v * Z3
    Y3 = sqrt_fp2_frac(u, v)
    Y3 = Y3 * Z3
    f0 = X3^2
    t0 = Z3^2
    fX = X3 * Z3
    fX = A * fX
    fX = fX + fX
    fX = fX + t0
    fX = fX + f0
    fX = fX + f0
    fX = fX + f0
    f0 = t0 - f0
    fX = fX * Z3
    fY = Y3 * Z3
    fY = fY + fY
    fY = -fY
    c = fY + fY
    fY = fY * Z3
    f0 = f0 * X3
    c = c * Y3
    fX = c * fX
    fY = c * fY
    f0 = c * f0
    
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "v" to polynomial, and get the coefficients
    P = A.polynomial()
    real, imag = P.coefficients(sparse=False)
    A0 = real
    A1 = imag
    
    while True:
        while pts_found < 2:
            r += 1
            x0, x1, y0, y1 = get_pt_on_curve(r, A0, A1)
            X = x0 + x1*j # Parse into Fp2
            Y = y0 + y1*j # Parse into Fp2
            f = fX * X
            t0 = fY * Y
            f = f + t0
            f = f + f0
            
            if not is_cube_fp2(f):
                X, Z = xDBLe(X, 1, A, 1, 372)
                u = A * Z
                u = u + X
                u = u * X
                v = Z^2
                u = u + v
                u = u * X
                v = v * Z
                Y = sqrt_fp2_frac(u, v)
                Y = Y * Z
                
                if pts_found == 0:
                    X1, Y1, Z1 = X, Y, Z
                    X3, Z3 = xTPLe(X1, Z1, A, 1, 238)
                else:
                    X2, Y2, Z2 = X, Y, Z
                    X4, Z4 = xTPLe(X2, Z2, A, 1, 238)
                
                pts_found += 1
        
        t0 = X3 * Z4
        t1 = X4 * Z3
        t0 = t0 - t1
        pts_found -= 1

        if t0 != 0:
            break
    
    return X1, Y1, Z1, X2, Y2, Z2

def recover_os(X1, Z1, X2, Z2, x, y, A):
    """
        Recovery as done in Okeya-Sakurai
        P1 := (X1,Y1,Z1)
        P2 := (X2,Y2,Z2)
        P := (x,y)
        P := P2-P1
    """
    
    X3 = 2*y*Z1*Z2*X1
    Y3 = Z2*((X1+x*Z1+2*A*Z1)*(X1*x+Z1)-2*A*Z1^2)-(X1-x*Z1)^2*X2
    Z3 = 2*y*Z1*Z2*Z1
    
    return X3, Y3, Z3

def recover_y(PK):
    """
        Recover the y-coordinates of the public key.
        The three resulting points are (simultaneously) correct up to sign.
    """
    
    A = get_A(PK[0], PK[1], PK[2])
    
    tmp = PK[2]^3+A*PK[2]^2+PK[2]
    phiXY = sqrt_fp2(tmp)
    phiX = [PK[2], phiXY, Fp2(1)]
    
    X, Y, Z = recover_os(PK[0], 1, PK[1], 1, PK[2], -phiXY, A)
    phiP = [X, Y, Z]
    
    X, Y, Z = recover_os(PK[1], 1, PK[0], 1, PK[2], phiXY, A)
    phiQ = [X, Y, Z]
    
    return phiP, phiQ, phiX, A

# Computes R+aS
def mont_twodim_scalarmult(a, R, S, A, A24):
    X0, Z0, X1, Z1 = mont_ladder(S[0], a, A24)
    X2, Y2, Z2 = recover_os(X0, Z0, X1, Z1, S[0], S[1], A)
    X3, Y3, Z3 = ADD(X2, Y2, Z2, R[0], R[1], 1, A)
    
    return X3, Y3, Z3
