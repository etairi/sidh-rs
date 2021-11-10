# Import Sage and other SIDH related modules
from sage.all import *
from sidh_field_arithmetic import *
from sidh_curve_and_isogeny_arithmetic import *
from sidh_pohlig_hellman import *

"""
    This file contains functions for public-key compression and decompression as
    well as adjusted functions for computing the shared secret that merge
    decompression into the shared secret computation. 
"""

# Turn off arithmetic proof
proof.arithmetic(False)

def compress_2_torsion(PK):
    phP, phQ, phX, A = recover_y(PK)
    XP, YP, ZP, XQ, YQ, ZQ = generate_2_torsion_basis(A)
    Zinv = mont_n_way_inv([phP[2], phQ[2]], 2)

    R1 = [XP, YP, ZP]
    R2 = [XQ, YQ, ZQ]
    phiP = [phP[0]*Zinv[0], phP[1]*Zinv[0]]
    phiQ = [phQ[0]*Zinv[1], phQ[1]*Zinv[1]]
    
    a0, b0, a1, b1 = ph_2(phiP, phiQ, R1, R2, A)
    if a0 < 0: 
        a0 += oA
    if b0 < 0:
        b0 += oA
    if a1 < 0:
        a1 += oA
    if b1 < 0:
        b1 += oA
        
    # comp is the compressed form of [phiP, phiQ]
    if a0 % lA != 0:
        a0inv = inverse_mod(a0, oA)
        comp = [0, (b0*a0inv) % oA, (a1*a0inv) % oA, (b1*a0inv) % oA]
    else:
        b0inv = inverse_mod(b0, oA)
        comp = [1, (a0*b0inv) % oA, (a1*b0inv) % oA, (b1*b0inv) % oA]
    
    # comp and A together are 1 + 3*372 + 2*751 = 2619 bits = 328 bytes.
    return comp, A

def compress_3_torsion(PK):
    phP, phQ, phX, A = recover_y(PK)
    XP, YP, ZP, XQ, YQ, ZQ = generate_3_torsion_basis(A)
    Zinv = mont_n_way_inv([ZP, ZQ, phP[2], phQ[2]], 4)

    R1 = [XP*Zinv[0], YP*Zinv[0]]
    R2 = [XQ*Zinv[1], YQ*Zinv[1]]
    phiP = [phP[0]*Zinv[2], phP[1]*Zinv[2]]
    phiQ = [phQ[0]*Zinv[3], phQ[1]*Zinv[3]]
    
    a0, b0, a1, b1 = ph_3(phiP, phiQ, R1, R2, A)

    if a0 < 0: 
        a0 += oB
    if b0 < 0:
        b0 += oB
    if a1 < 0:
        a1 += oB
    if b1 < 0:
        b1 += oB
        
    # comp is the compressed form of [phiP, phiQ]
    if a0 % lB != 0:
        a0inv = inverse_mod(a0, oB)
        comp = [0, (b0*a0inv) % oB, (a1*a0inv) % oB, (b1*a0inv) % oB]
    else:
        b0inv = inverse_mod(b0, oB)
        comp = [1, (a0*b0inv) % oB, (a1*b0inv) % oB, (b1*b0inv) % oB]
    
    # comp and A together are 1 + 3*379 + 2*751 = 2640 bits = 330 bytes.
    return comp, A

def decompress_2_torsion_fast(SK, comp, A):
    X1, Y1, Z1, X2, Y2, Z2 = generate_2_torsion_basis(A)
    
    # Normalize basis points
    invs = mont_n_way_inv([Z1, Z2], 2)
    R1X = X1 * invs[0]
    R1Y = Y1 * invs[0]
    R2X = X2 * invs[1]
    R2Y = Y2 * invs[1]
    R1 = [R1X, R1Y]
    R2 = [R2X, R2Y]
    
    A24 = A + 2
    A24 = A24 / 2
    A24 = A24 / 2
    
    if comp[0] == 0:
        inv = inverse_mod(1 + SK*comp[2], oA)
        scal = ((comp[1] + SK*comp[3]) * inv) % oA
        X0, Y0, Z0 = mont_twodim_scalarmult(scal, R1, R2, A, A24)
    else:
        inv = inverse_mod(1 + SK*comp[3], oA)
        scal = ((comp[1] + SK*comp[2]) * inv) % oA
        X0, Y0, Z0 = mont_twodim_scalarmult(scal, R2, R1, A, A24)
    
    return X0, Z0

def decompress_3_torsion_fast(SK, comp, A):
    X1, Y1, Z1, X2, Y2, Z2 = generate_3_torsion_basis(A)
    
    # Normalize basis points
    invs = mont_n_way_inv([Z1, Z2], 2)
    R1X = X1 * invs[0]
    R1Y = Y1 * invs[0]
    R2X = X2 * invs[1]
    R2Y = Y2 * invs[1]
    R1 = [R1X, R1Y]
    R2 = [R2X, R2Y]
    
    A24 = A + 2
    A24 = A24 / 2
    A24 = A24 / 2
    
    if comp[0] == 0:
        inv = inverse_mod(1 + SK*comp[2], oB)
        scal = ((comp[1] + SK*comp[3]) * inv) % oB
        X0, Y0, Z0 = mont_twodim_scalarmult(scal, R1, R2, A, A24)
    else:
        inv = inverse_mod(1 + SK*comp[3], oB)
        scal = ((comp[1] + SK*comp[2]) * inv) % oB
        X0, Y0, Z0 = mont_twodim_scalarmult(scal, R2, R1, A, A24)
    
    return X0, Z0

def shared_secret_alice_decompression(SK_Alice, PK_Bob_comp_0, PK_Bob_comp_1, params, splits, MAX):
    """
        This function generates Alice's shared secret from her secret key and Bob's
        compressed public key. It uses the optimal way of traversing the isogeny tree as
        described by De Feo, Jao and Plut. 

        Input: 
        - Alice's secret key SK_Alice, a random even number between 1 and oA-1,
        - Bob's compressed public key PK_Bob_comp=[PK_Bob_comp_0,PK_Bob_comp_1],
        - the parameter "splits", a vector that guides the optimal route through the 
          isogeny tree; it is generated individually for Alice using 
          "optimalstrategies.m" and the ratios of 4-isogeny evaluation versus 
          multiplication-by-4,
        - the parameter "MAX", the maximum number of multiplication-by-4
          computations.

        Output: 
        - Alice's shared secret: the j-invariant of E_AB.
    """
    
    A = PK_Bob_comp_1
    RX, RZ = decompress_2_torsion_fast(SK_Alice, PK_Bob_comp_0, A)
    C = 1 # Starting on Bob's Montgomery curve
    
    isos, mulm = 0, 0
    
    # The first iteration is different so not in the main loop
    RX, RZ, A, C = first_4_isog(RX, RZ, A); isos += 1
    
    pts = []
    index = 0
    
    # Alice's main loop
    for row in [1..MAX-1]:
        # Multiply (RX:RZ) until it has order 4, and store intermediate points
        while index < (MAX - row):
            pts.append([RX, RZ, index])
            m = splits[MAX-index-row]
            RX, RZ = xDBLe(RX, RZ, A, C, 2*m); mulm += m
            index += m
        
        # Compute the 4-isogeny based on kernel (RX:RZ)
        A, C, consts = get_4_isog(RX, RZ)
        # Evaluate the 4-isogeny at every point in pts
        for i in [0..len(pts)-1]:
            pts[i][0], pts[i][1] = eval_4_isog(consts, pts[i][0], pts[i][1])
            isos += 1
        
        # R becomes the last point in pts and then pts is pruned
        RX = pts[len(pts)-1][0]
        RZ = pts[len(pts)-1][1]
        index = ZZ(pts[len(pts)-1][2])
        
        pts.pop()
    
    # Compute the last 4-isogeny
    A, C, consts = get_4_isog(RX, RZ)
    
    # Compute the j-invariant of E_AB
    shared_secret_alice = j_inv(A, C)
    
    print "Alice FAST secret requires", mulm, "muls-by-4 and", isos, "4-isogenies"
    
    return shared_secret_alice

def shared_secret_bob_decompression(SK_Bob, PK_Alice_comp_0, PK_Alice_comp_1, params, splits, MAX):
    """
        This function generates Bob's shared secret from his secret key and Alice's
        public key. It uses the optimal way of traversing the isogeny tree as
        described by De Feo, Jao and Plut. 

        Input: 
        - Bob's secret key SK_Bob, a random number between 1 and oB-1,
        - Alice's public key PK_Alice=[phi_A(xPB),phi_A(xQB),phi_A(x(QB-PB))],
        - the parameter "splits", a vector that guides the optimal route through the 
          isogeny tree; it is generated individually for Bob using 
          "optimalstrategies.m" and the ratios of 3-isogeny evaluation versus 
          multiplication-by-3,
        - the parameter "MAX", the maximum number of multiplication-by-3
          computations.

        Output: 
        - Bob's shared secret: the j-invariant of E_BA.
    """
    
    A = PK_Alice_comp_1
    RX, RZ = decompress_3_torsion_fast(SK_Bob, PK_Alice_comp_0, A)
    C = 1 # Starting on Alice's Montgomery curve
    
    isos, mulm = 0, 0
    
    pts = []
    index = 0
    
    # Bob's main loop
    for row in [1..MAX-1]:
        # Multiply (RX:RZ) until it has order 3, and store intermediate points
        while index < (MAX - row):
            pts.append([RX, RZ, index])
            m = splits[MAX-index-row]
            RX, RZ = xTPLe(RX, RZ, A, C, m); mulm += m
            index += m
        
        # Compute the 3-isogeny based on kernel (RX:RZ)
        A, C = get_3_isog(RX, RZ)
        
        # Evaluate the 3-isogeny at every point in pts
        for i in [0..len(pts)-1]:
            pts[i][0], pts[i][1] = eval_3_isog(RX, RZ, pts[i][0], pts[i][1])
            isos += 1
        
        # R becomes the last point in pts and then pts is pruned
        RX = pts[len(pts)-1][0]
        RZ = pts[len(pts)-1][1]
        index = ZZ(pts[len(pts)-1][2])
        
        pts.pop()
        
    # Compute the last 3-isogeny
    A, C = get_3_isog(RX, RZ)
    
    # Compute the j Invariant of E_BA
    shared_secret_bob = j_inv(A, C)
    
    print "Bob FAST secret requires", mulm, "muls-by-3 and", isos, "3-isogenies"
    
    return shared_secret_bob
