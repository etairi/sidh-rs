# Import Sage and other SIDH related modules
from sage.all import *
from sidh_field_arithmetic import *

"""
    This file implements the Tate pairing on the 2- and 3-torsion groups,
    respectively. The Miller loops are done as doubling-only and tripling-only
    loops using parabolas during the 3-torsion pairing. Functions are tailored
    towards doing 5 pairings at a time to be used for the Pohlig-Hellman DL
    compuation for public-key compression.  
"""

# Turn off arithmetic proof
proof.arithmetic(False)

def dbl_and_line(T, A):
    """
      Cost: 9M+5S+7a+1s
      Explicit formulas:
        X2 := T[1]; XZ := T[2]; Z2 := T[3]; YZ := T[4];

        ly := (2*YZ)^2; 
        l0 := 2*YZ*(X2-Z2);
        lx := YZ*ly+XZ*l0;

        ly_ := XZ*ly; 
        l0_ := X2*l0; 
        v0 := (X2-Z2)^2; 
        v0_ := XZ*v0; 

        X2_ := v0^2; 
        XZ_ := l0^2; 
        Z2_ := ly^2; 
        YZ_ := l0*(v0 + 2*XZ*( 4*XZ + A*(X2+Z2))); 
    """
    
    X2, XZ, Z2, YZ = T[0], T[1], T[2], T[3]
    
    _X2 = YZ + YZ
    ly = _X2^2
    
    l0 = X2 - Z2
    v0 = l0^2
    l0 = _X2 * l0
    
    lx = XZ * l0
    _X2 = YZ * ly
    lx = _X2 + lx
    
    _YZ = X2 + Z2
    _YZ = A * _YZ
    _X2 = XZ + XZ
    _YZ = _X2 + _YZ
    _YZ = _X2 + _YZ
    _YZ = _X2 * _YZ
    
    _X2 = v0^2
    _XZ = l0^2
    _Z2 = ly^2
    _YZ = v0 + _YZ
    _YZ = l0 * _YZ
    
    ly = XZ * ly
    l0 = X2 * l0
    v0 = XZ * v0
    
    return [_X2, _XZ, _Z2, _YZ], [lx, ly, l0], [v0]

def triple_and_parabola(T, A):
    """
      Cost: 19M+6S+15a+6s
      Explicit formulas:
        X2 := T[1]; XZ := T[2]; Z2 := T[3]; YZ := T[4];

        tYZ := YZ+YZ; 
        tYZ2 := tYZ^2; S +:= 1;
        X2mZ22 := (X2-Z2)^2; S +:= 1;
        X2pZ22 := (X2+Z2)^2; S +:= 1;
        AXZ := A*XZ; M +:= 1;

        ly  := tYZ*tYZ2; M +:= 1;
        lx2 := 2*X2*( X2+X2+AXZ+AXZ+Z2+Z2 ) - X2mZ22; M +:= 1;
        lx1 := X2mZ22 + 2*( X2pZ22 + AXZ*( X2+X2+AXZ+AXZ+Z2+Z2+X2+Z2) ); M +:= 1;
        lx0 := X2pZ22 - 2*( X2mZ22 - Z2*( 2*(AXZ+Z2) ) ); M +:= 1;

        lx2_ := Z2*lx2; M +:= 1;
        lx1_ := 2*XZ*lx1; M +:= 1;
        lx0_ := X2*lx0; M +:= 1;

        lx02 := lx0^2; S +:= 1;
        lx22 := lx2^2; S +:= 1;
        lx04 := lx02^2; S +:= 1;
        lx0lx1 := lx0*lx1; M +:= 1;
        lx0_lx2 := lx0_*lx2; M +:= 1;
        lylx22 := ly*lx22; M +:= 1;
        X2lx04 := X2*lx04; M +:= 1;

        X2_ := ly * X2lx04; M +:= 1;
        XZ_ := XZ * lylx22 * lx02; M +:= 2;
        Z2_ := Z2 * lylx22 * lx22; M +:= 2;
        YZ_ := - lx2_ * ( X2lx04 + lx0_lx2 * ( 2*lx0lx1 + lx22 ) ); M +:= 2;

        vx:=Z2_;
        v0:=-XZ_;
    """
    
    X2, XZ, Z2, YZ = T[0], T[1], T[2], T[3]
    
    ly = YZ + YZ
    lx2 = ly^2
    ly = ly * lx2
    
    AXZ = A * XZ
    t0 = AXZ + Z2
    t0 = t0 + t0
    t1 = X2 + Z2
    t2 = X2 + X2
    t3 = X2 - Z2
    t3 = t3^2
    t4 = t2 + t0
    lx2 = t2 * t4
    lx2 = lx2 - t3
    
    lx1 = t4 + t1
    t1 = t1^2
    lx1 = AXZ * lx1
    lx1 = t1 + lx1
    lx1 = lx1 + lx1
    lx1 = t3 + lx1
    
    lx0 = Z2 * t0
    lx0 = t3 - lx0
    lx0 = lx0 + lx0
    lx0 = t1 - lx0
    
    _lx2 = Z2 * lx2
    _lx1 = XZ * lx1
    _lx1 = _lx1 + _lx1
    _lx0 = X2 * lx0
    # _lx2, _lx1, _lx0 done
    
    t3 = lx2^2
    t2 = ly * t3
    
    t4 = lx0^2
    t0 = t4^2
    t0 = X2 * t0
    
    _X2 = ly * t0
    _XZ = XZ * t2
    _XZ = _XZ * t4
    _Z2 = Z2 * t2
    _Z2 = _Z2 * t3
    t2 = lx0 * lx1
    _YZ = t2 + t2
    _YZ = _YZ + t3
    t2 = _lx0 * lx2
    _YZ = t2 * _YZ
    _YZ = t0 + _YZ
    _YZ = _lx2 * _YZ
    _YZ = -_YZ
    # _X2, _XZ, _Z2, _YZ done
    
    vx = _Z2
    v0 = -_XZ
    # vx, v0 done
    
    return [_X2, _XZ, _Z2, _YZ], [ly, _lx2, _lx1, _lx0], [vx, v0]

def square_and_absorb_line(n, d, L, V, x, y): # lx = ly
    """
      Cost: 5M+2S+1a+2s
      Explicit formulas:
          lx := L[1]; ly := L[2]; l0 := L[3]; v0 := V[1];
          n := n^2*(ly*y-lx*x+l0);
          d := d^2*(ly*x-v0);
    """
    
    lx, ly, l0, v0 = L[0], L[1], L[2], V[0]
    
    n = n^2
    d = d^2
    l = lx * x
    v = ly * y
    l = v -l
    l = l + l0
    v = ly * x
    v = v - v0
    n = n * l
    d = d * v
    
    return n, d

def cube_and_absorb_parab(n ,d, L, V, x, y):
    """
      Cost: 10M+2S+4a
      Explicit formulas:
          ly := L[1]; lx2 := L[2]; lx1 := L[3]; lx0 := L[4];
          vx := V[1]; v0 := V[2];

          n := n^3;
          d := d^3;
          ln := (ly*y + lx2 + lx1*x + lx0*x^2)*v0;
          ld := (vx + v0*x)*lx0*x;
          n := n*ln;
          d := d*ld;
    """
    
    ly, lx2, lx1, lx0 = L[0], L[1], L[2], L[3]
    vx, v0 = V[0], V[1]
    
    ln = n^2
    n = n * ln
    ld = d^2
    d = d * ld
    
    ln = lx0 * x
    ld = v0 * x
    ld = vx + ld
    ld = ld * ln
    
    ln = lx1 + ln
    ln = x * ln
    t = ly * y
    ln = lx2 + ln
    ln = t + ln
    ln = ln * v0
    
    n = n * ln
    d = d * ld
    
    return n, d

def final_dbl_iteration(n, d, X, Z, x):
    """
      Cost: 7M+3S+2a
      Explicit formulas:
          n:=n^2*(Z*x-X);
          d:=d^2*Z;
    """
    
    n = n^2
    d = d^2
    d = d * Z
    l = Z * x
    l = l - X
    n = n * l
    
    return n, d

def final_tpl_iteration(n, d, l, mu, D, x, y): # l = lambda
    """
      Cost: 7M+3S+2a
      Explicit formulas:
        n:=n^3; d:=d^3;
        ln:=(D*y+lambda*x+mu*x^2); ld:=mu*x^2;
        n:=n*ln; d:=d*ld;
    """
    
    ln = n^2
    n = n * ln
    ld = d^2
    d = d * ld
    
    ld = x^2
    ld = mu * ld
    t = l * x
    ln = t + ld
    t = D * y
    ln = t + ln
    
    n = n * ln
    d = d * ld
    
    return n, d

def final_triple(P, A):
    """
      Cost: 4M+3S+7a+1s
      Explicit formulas:
          X := P[2]; Y := P[4]; Z := P[3];
          lambda := 2*Y*Z*(3*X^2+2*A*X*Z+Z^2);
          mu := 2*X*Y*(Z^2-X^2);
          D := (2*Y*Z)^2;
    """
    
    X, Y, Z = P[1], P[3], P[2]
    
    X2 = X^2
    tX2 = X2 + X2
    AX2 = A * X2
    XZ = X * Z
    Y2 = Y^2
    tXZ = XZ + XZ
    tAXZ = A * tXZ
    Z2 = Z^2
    YZ = Y * Z
    
    # l = lambda
    l = X2 + Z2
    l = l + tX2
    l = l + tAXZ
    mu = tXZ - Y2
    mu = mu + AX2
    D = YZ + YZ
    
    return l, mu, D

def final_exponentiation_2_torsion(n, d, n_inv, d_inv):
    n = n * d_inv
    n = inv_fp2_cycl(n)
    d = d * n_inv
    n = n * d
    
    for j in [1..239]:
        n = cube_fp2_cycl(n)
    
    return n

def final_exponentiation_3_torsion(n, d, n_inv, d_inv):
    n = n * d_inv
    n = inv_fp2_cycl(n)
    d = d * n_inv
    n = n * d
    
    for j in [1..372]:
        n = sqr_fp2_cycl(n)
    
    return n

def tate_pairings_2_torsion(R1, R2, P, Q, A):
    x1, y1, z1 = R1[0], R1[1], R1[2]
    x2, y2, z2 = R2[0], R2[1], R2[2]
    xP, yP = P[0], P[1]
    xQ, yQ = Q[0], Q[1]
    
    T1 = [x1^2, x1*z1, z1^2, y1*z1]
    T2 = [x2^2, x2*z2, z2^2, y2*z2]
    x2, y2 = x2/z2, y2/z2
    
    n1, d1 = 1, 1
    n2, d2 = 1, 1
    n3, d3 = 1, 1
    n4, d4 = 1, 1
    n5, d5 = 1, 1
    
    for i in range(371, 0, -1):
        T1, L1, V1 = dbl_and_line(T1, A) # vx = ly
        T2, L2, V2 = dbl_and_line(T2, A) # vx = ly
        
        n1, d1 = square_and_absorb_line(n1, d1, L1, V1, x2, y2)
        n2, d2 = square_and_absorb_line(n2, d2, L1, V1, xP, yP)
        n3, d3 = square_and_absorb_line(n3, d3, L1, V1, xQ, yQ)
        n4, d4 = square_and_absorb_line(n4, d4, L2, V2, xP, yP)
        n5, d5 = square_and_absorb_line(n5, d5, L2, V2, xQ, yQ)
    
    X1, Z1 = T1[1], T1[2]
    X2, Z2 = T2[1], T2[2]
    
    n1, d1 = final_dbl_iteration(n1, d1, X1, Z1, x2)
    n2, d2 = final_dbl_iteration(n2, d2, X1, Z1, xP)
    n3, d3 = final_dbl_iteration(n3, d3, X1, Z1, xQ)
    n4, d4 = final_dbl_iteration(n4, d4, X2, Z2, xP)
    n5, d5 = final_dbl_iteration(n5, d5, X2, Z2, xQ)
    
    invs = mont_n_way_inv([n1, d1, n2, d2, n3, d3, n4, d4, n5, d5], 10)
    
    n1 = final_exponentiation_2_torsion(n1, d1, invs[0], invs[1])
    n2 = final_exponentiation_2_torsion(n2, d2, invs[2], invs[3])
    n3 = final_exponentiation_2_torsion(n3, d3, invs[4], invs[5])
    n4 = final_exponentiation_2_torsion(n4, d4, invs[6], invs[7])
    n5 = final_exponentiation_2_torsion(n5, d5, invs[8], invs[9])
    
    return n1, n2, n3, n4, n5

def tate_pairings_3_torsion_triple(R1, R2, P, Q, A): # 3^e pairing
    e = 239
    
    x1, y1 = R1[0], R1[1]
    x2, y2 = R2[0], R2[1]
    xP, yP = P[0], P[1]
    xQ, yQ = Q[0], Q[1]
    
    n1, d1 = 1, 1
    n2, d2 = 1, 1
    n3, d3 = 1, 1
    n4, d4 = 1, 1
    n5, d5 = 1, 1
    
    T1 = [x1^2, x1, 1, y1]
    T2 = [x2^2, x2, 1, y2]
    
    for i in range(e, 1, -1):
        T1, L1, V1 = triple_and_parabola(T1, A)
        T2, L2, V2 = triple_and_parabola(T2, A)
        
        n1, d1 = cube_and_absorb_parab(n1, d1, L1, V1, x2, y2)
        n2, d2 = cube_and_absorb_parab(n2, d2, L1, V1, xP, yP)
        n3, d3 = cube_and_absorb_parab(n3, d3, L1, V1, xQ, yQ)
        n4, d4 = cube_and_absorb_parab(n4, d4, L2, V2, xP, yP)
        n5, d5 = cube_and_absorb_parab(n5, d5, L2, V2, xQ, yQ)
    
    lambda1, mu1, D1 = final_triple(T1, A)
    lambda2, mu2, D2 = final_triple(T2, A)
    
    n1, d1 = final_tpl_iteration(n1, d1, lambda1, mu1, D1, x2, y2)
    n2, d2 = final_tpl_iteration(n2, d2, lambda1, mu1, D1, xP, yP)
    n3, d3 = final_tpl_iteration(n3, d3, lambda1, mu1, D1, xQ, yQ)
    n4, d4 = final_tpl_iteration(n4, d4, lambda2, mu2, D2, xP, yP)
    n5, d5 = final_tpl_iteration(n5, d5, lambda2, mu2, D2, xQ, yQ)
    
    invs = mont_n_way_inv([n1, d1, n2, d2, n3, d3, n4, d4, n5, d5], 10)
    
    n1 = final_exponentiation_3_torsion(n1, d1, invs[0], invs[1])
    n2 = final_exponentiation_3_torsion(n2, d2, invs[2], invs[3])
    n3 = final_exponentiation_3_torsion(n3, d3, invs[4], invs[5])
    n4 = final_exponentiation_3_torsion(n4, d4, invs[6], invs[7])
    n5 = final_exponentiation_3_torsion(n5, d5, invs[8], invs[9])
    
    return n1, n2, n3, n4, n5
