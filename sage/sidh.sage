# Import Sage and other SIDH related modules
from sage.all import *
from sidh_parameters import *
from sidh_field_arithmetic import *
from sidh_curve_and_isogeny_arithmetic import *

"""
    This file contains the key exchange functions for SIDH without public key
    compression. Simple functions are slow but follow the straightforward
    multiplication-based strategy for isogeny tree traversal. 
"""

# Turn off arithmetic proof
proof.arithmetic(False)

# Alice key generation, simple but slow version
def keygen_alice_simple(SK_Alice, params):
    """
        This function generates Alice's public key from her secret key and the 
        public scheme parameters. It uses a simple but costly loop for traversing 
        the isogeny tree.

        Input: 
        - Alice's secret key SK_Alice, which is a random even number between 1 and 
          oA-1,
        - three public parameters params=[XPB,XPA,YPA]: the x-coordinate of PB, 
          and both coordinates of PA.

        Output: 
        - Alice's public key [phi_A(x(PB)),phi_A(x(QB)),phi_A(x(QB-PB))].
    """
    
    A, C = 0, 1 # The starting Montgomery curve (A:C) = (0:1)
    phiPX, phiPZ = params[0], 1
    phiQX, phiQZ = -phiPX, 1    # Q=(-xP,yP), tau(P) but yP instead of yP*i, the "*i" is handled implicitly
    phiDX, phiDZ = distort_and_diff(phiPX) # (phiDX:phiDZ):=x(Q-P)
    
    # Computes x(R)=(RX:RZ) via secret_pt function
    RX0, RX1, RZ = secret_pt(params[1], params[2], SK_Alice, Alice)
    RX = RX0 + RX1*j
    
    isos, mulm = 0, 0
    
    # The first iteration is different, so not in the main loop
    phiPX, phiPZ, _, _ = first_4_isog(phiPX, phiPZ, A); isos += 1
    phiQX, phiQZ, _, _ = first_4_isog(phiQX, phiQZ, A); isos += 1
    phiDX, phiDZ, _, _ = first_4_isog(phiDX, phiDZ, A); isos += 1
    RX, RZ, A, C = first_4_isog(RX, RZ, A); isos += 1
    
    # Alice's main loop
    for e in range(eA-4, -1, -2):
        SX, SZ = xDBLe(RX, RZ, A, C, e); mulm += e / 2 # Computes S = [2^e]R
        A, C, consts = get_4_isog(SX, SZ) # Compute the 4-isogeny phi
        RX, RZ = eval_4_isog(consts, RX, RZ); isos += 1 # R = phi(R)
        phiPX, phiPZ = eval_4_isog(consts, phiPX, phiPZ); isos += 1; # P = phi(P)
        phiQX, phiQZ = eval_4_isog(consts, phiQX, phiQZ); isos += 1; # Q = phi(Q)
        phiDX, phiDZ = eval_4_isog(consts, phiDX, phiDZ); isos += 1; # R = phi(R)
    
    # Normalize everything via a 3-way simultaneous inversion
    phiPZ, phiQZ, phiDZ = inv_3_way(phiPZ, phiQZ, phiDZ)
    phiPX = phiPX * phiPZ
    phiQX = phiQX * phiQZ
    phiDX = phiDX * phiDZ
    
    PK_Alice = [phiPX, phiQX, phiDX] # 3 values in Fp2
    
    print "Alice simple keygen requires", mulm, "muls-by-4 and", isos, "4-isogenies"
    
    return PK_Alice

# Alice fast keygen
def keygen_alice_fast(SK_Alice, params, splits, MAX):
    """
        This function generates Alice's public key from her secret key and the
        public scheme parameters. It uses the optimal way of traversing the
        isogeny tree as described by De Feo, Jao and Plut. 

        Input: 
        - Alice's secret key SK_Alice, which is a random even number between 1 and 
          oA-1,
        - three public parameters params=[XPB,XPA,YPA]: the x-coordinate of PB, 
          and both coordinates of PA,
        - the parameter "splits", a vector that guides the optimal route through
          the isogeny tree; it is generated individually for Alice using
          "optimalstrategies.mag" and the ratios of 4-isogeny evaluation versus 
          multiplication-by-4,
        - the parameter "MAX", the maximum number of multiplication-by-4
          computations.

        Output: 
        - Alice's public key [phi_A(x(PB)),phi_A(x(QB)),phi_A(x(QB-PB))].
    """
    
    A, C = 0, 1 # The starting Montgomery curve (A:C) = (0:1)
    phiPX, phiPZ = params[0], 1
    phiQX, phiQZ = -phiPX, 1 # Q=(-xP,yP), tau(P) but yP instead of yP*i, the "*i" is handled implicitly
    phiDX, phiDZ = distort_and_diff(phiPX) # (phiDX:phiDZ):=x(Q-P)
    
    # Computes x(R)=(RX:RZ) via secret_pt function
    RX0, RX1, RZ = secret_pt(params[1], params[2], SK_Alice, Alice)
    RX = RX0 + RX1*j
    
    isos, mulm = 0, 0
    
    # The first iteration is different, so not in the main loop
    phiPX, phiPZ, _, _ = first_4_isog(phiPX, phiPZ, A); isos += 1
    phiQX, phiQZ, _, _ = first_4_isog(phiQX, phiQZ, A); isos += 1
    phiDX, phiDZ, _, _ = first_4_isog(phiDX, phiDZ, A); isos += 1
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
        
        # Evaluate the 4-isogeny at Bob's (intermediate) points
        # x(P), x(Q), x(Q-P)
        phiPX, phiPZ = eval_4_isog(consts, phiPX, phiPZ); isos += 1
        phiQX, phiQZ = eval_4_isog(consts, phiQX, phiQZ); isos += 1
        phiDX, phiDZ = eval_4_isog(consts, phiDX, phiDZ); isos += 1
        
        # R becomes the last point in pts and then pts is pruned
        RX = pts[len(pts)-1][0]
        RZ = pts[len(pts)-1][1]
        index = ZZ(pts[len(pts)-1][2])
        
        pts.pop()
    
    # Compute and evaluate the last 4-isogeny
    A, C, consts = get_4_isog(RX, RZ)
    phiPX, phiPZ = eval_4_isog(consts, phiPX, phiPZ); isos += 1
    phiQX, phiQZ = eval_4_isog(consts, phiQX, phiQZ); isos += 1
    phiDX, phiDZ = eval_4_isog(consts, phiDX, phiDZ); isos += 1
    
    # Normalize everything via a 3-way simultaneous inversion
    phiPZ, phiQZ, phiDZ = inv_3_way(phiPZ, phiQZ, phiDZ)
    phiPX = phiPX * phiPZ
    phiQX = phiQX * phiQZ
    phiDX = phiDX * phiDZ
    
    PK_Alice = [phiPX, phiQX, phiDX] # 3 values in Fp2
    
    print "Alice FAST keygen requires", mulm, "muls-by-4 and", isos, "4-isogenies"
    
    return PK_Alice

# Bob key generation, simple but slow version
def keygen_bob_simple(SK_Bob, params):
    """
        This function generates Bob's public key from her secret key and the 
        public scheme parameters. It uses a simple but costly loop for traversing 
        the isogeny tree.

        Input: 
        - Bob's secret key SK_Bob, which is a random value between 1 and oB-1, 
        - three public parameters params=[XPA,XPB,YPB]: the x-coordinate of PA, and 
          both coordinates of PB.

        Output: 
        - Bob's public key [phi_B(x(PA)),phi_B(x(QA)),phi_B(x(QA-PA))].
    """
    
    A, C = 0, 1 # The starting Montgomery curve (A:C) = (0:1)
    phiPX, phiPZ = params[0], 1
    phiQX, phiQZ = -phiPX, 1 # Q=(-xP,yP), tau(P) but yP instead of yP*i, the "*i" is handled implicitly
    phiDX, phiDZ = distort_and_diff(phiPX) # (phiDX:phiDZ):=x(Q-P)
    
    # Computes x(R)=(RX:RZ) via secret_pt function
    RX0, RX1, RZ = secret_pt(params[1], params[2], SK_Bob, Bob)
    RX = RX0 + RX1*j
    
    isos, mulm = 0, 0
    
    # Bob's main loop
    for e in range(eB-1, -1, -1):
        SX, SZ = xTPLe(RX, RZ, A, C, e); mulm += e # Computes S=[3^e]R
        A, C = get_3_isog(SX, SZ) # Computes the 3-isogeny phi
        RX, RZ = eval_3_isog(SX, SZ, RX, RZ); isos += 1 # R=phi(R)
        phiPX, phiPZ = eval_3_isog(SX, SZ, phiPX, phiPZ); isos += 1 # P=phi(P)
        phiQX, phiQZ = eval_3_isog(SX, SZ, phiQX, phiQZ); isos += 1 # Q=phi(Q)
        phiDX, phiDZ = eval_3_isog(SX, SZ, phiDX, phiDZ); isos += 1 # R=phi(R)
    
    # Normalize everything via a 3-way simultaneous inversion
    phiPZ, phiQZ, phiDZ = inv_3_way(phiPZ, phiQZ, phiDZ)
    phiPX = phiPX * phiPZ
    phiQX = phiQX * phiQZ
    phiDX = phiDX * phiDZ
    
    PK_Bob = [phiPX, phiQX, phiDX] #3 values in Fp2
    
    print "Bob simple keygen requires", mulm, "muls-by-3 and", isos, "3-isogenies"
    
    return PK_Bob

# Bob fast keygen
def keygen_bob_fast(SK_Bob, params, splits, MAX):
    """
        This function generates Bob's public key from his secret key and the 
        public scheme parameters. It uses the optimal way of traversing the
        isogeny tree as described by De Feo, Jao and Plut. 

        Input: 
        - Bob's secret key SK_Bob, which is a random value between 1 and oB-1, 
        - three public parameters params=[XPA,XPB,YPB]: the x-coordinate of PA, and 
          both coordinates of PB.
        - the parameter "splits", a vector that guides the optimal route through the 
          isogeny tree; it is generated individually for Bob using 
          "optimalstrategies.m" and the ratios of 3-isogeny evaluation versus 
          multiplication-by-3,
        - the parameter "MAX", the maximum number of multiplication-by-3
          computations.

        Output: 
        - Bob's public key [phi_B(x(PA)),phi_B(x(QA)),phi_B(x(QA-PA))].
    """
    
    A, C = 0, 1 # The starting Montgomery curve (A:C) = (0:1)
    phiPX, phiPZ = params[0], 1
    phiQX, phiQZ = -phiPX, 1 # Q=(-xP,yP), tau(P) but yP instead of yP*i, the "*i" is handled implicitly
    phiDX, phiDZ = distort_and_diff(phiPX) # (phiDX:phiDZ):=x(Q-P)
    
    # Computes x(R)=(RX:RZ) via secret_pt function
    RX0, RX1, RZ = secret_pt(params[1], params[2], SK_Bob, Bob)
    RX = RX0 + RX1*j
    
    pts = []
    index = 0
    
    isos, mulm = 0, 0
    
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
        
        # Evaluate the 3-isogeny at Alice's (intermediate) points 
        # x(P), x(Q), x(Q-P)
        phiPX, phiPZ = eval_3_isog(RX, RZ, phiPX, phiPZ); isos += 1
        phiQX, phiQZ = eval_3_isog(RX, RZ, phiQX, phiQZ); isos += 1
        phiDX, phiDZ = eval_3_isog(RX, RZ, phiDX, phiDZ); isos += 1
        
        # R becomes the last point in pts and then pts is pruned
        RX = pts[len(pts)-1][0]
        RZ = pts[len(pts)-1][1]
        index = ZZ(pts[len(pts)-1][2])
        
        pts.pop()
    
    # Compute and evaluate the last 3-isogeny
    A, C = get_3_isog(RX, RZ)
    phiPX, phiPZ = eval_3_isog(RX, RZ, phiPX, phiPZ); isos += 1
    phiQX, phiQZ = eval_3_isog(RX, RZ, phiQX, phiQZ); isos += 1
    phiDX, phiDZ = eval_3_isog(RX, RZ, phiDX, phiDZ); isos += 1
    
    # Normalize everything via a 3-way simultaneous inversion
    phiPZ, phiQZ, phiDZ = inv_3_way(phiPZ, phiQZ, phiDZ)
    phiPX = phiPX * phiPZ
    phiQX = phiQX * phiQZ
    phiDX = phiDX * phiDZ
    
    PK_Bob = [phiPX, phiQX, phiDX] # 3 values in Fp2
    
    print "Bob FAST keygen requires", mulm, "muls-by-3 and", isos, "3-isogenies"
    
    return PK_Bob

# Alice shared secret, simple but slow version
def shared_secret_alice_simple(SK_Alice, PK_Bob):
    """
        This function generates Alice's shared secret from her secret key and Bob's
        public key. It uses a simple but costly loop for traversing the isogeny
        tree.

        Input: 
        - Alice's secret key SK_Alice, a random even number between 1 and oA-1,
        - Bob's public key PK_Bob=[phi_B(x(PA)),phi_B(x(QA)),phi_B(x(QA-PA))].

        Output: 
        - Alice's shared secret: the j-invariant of E_AB.
    """
    
    A = get_A(PK_Bob[0], PK_Bob[1], PK_Bob[2])
    C = 1 # Starting on Bob's Montgomery curve
    
    # Computes R=phi_B(xPA)+SK_Alice*phi_B(xQA) via 3 point ladder
    RX, RZ = LADDER_3_pt(SK_Alice, PK_Bob[0], PK_Bob[1], PK_Bob[2], A, Alice)
    
    isos, mulm = 0, 0
    
    # The first iteration is different so not in the main loop
    RX, RZ, A, C = first_4_isog(RX, RZ, A); isos += 1
    
    # Alice's main loop
    for e in range(eA-4, -1, -2):
        SX, SZ = xDBLe(RX, RZ, A, C, e); mulm += e / 2 # Computes S=[2^e]R
        A, C, consts = get_4_isog(SX, SZ) # Computes the 4-isogeny phi
        RX, RZ = eval_4_isog(consts, RX, RZ); isos += 1 # R=phi(R)
    
    # Compute the j-invariant of E_AB
    shared_secret_alice = j_inv(A, C)
    
    print "Alice simple secret requires", mulm, "muls-by-4 and", isos, "4-isogenies"
    
    return shared_secret_alice

# Alice shared secret fast
def shared_secret_alice_fast(SK_Alice, PK_Bob, params, splits, MAX):
    """
        This function generates Alice's shared secret from her secret key and Bob's
        public key. It uses the optimal way of traversing the isogeny tree as
        described by De Feo, Jao and Plut. 

        Input: 
        - Alice's secret key SK_Alice, a random even number between 1 and oA-1,
        - Bob's public key PK_Bob=[phi_B(x(PA)),phi_B(x(QA)),phi_B(x(QA-PA))],
        - the parameter "splits", a vector that guides the optimal route through the 
          isogeny tree; it is generated individually for Alice using 
          "optimalstrategies.m" and the ratios of 4-isogeny evaluation versus 
          multiplication-by-4,
        - the parameter "MAX", the maximum number of multiplication-by-4
          computations.

        Output: 
        - Alice's shared secret: the j-invariant of E_AB.
    """
    
    A = get_A(PK_Bob[0], PK_Bob[1], PK_Bob[2])
    C = 1 # Starting on Bob's Montgomery curve
    
    # Computes R=phi_B(xPA)+SK_Alice*phi_B(xQA) via 3 point ladder
    RX, RZ = LADDER_3_pt(SK_Alice, PK_Bob[0], PK_Bob[1], PK_Bob[2], A, Alice)
    
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

# Bob shared secret, simple but slow version
def shared_secret_bob_simple(SK_Bob, PK_Alice):
    """
        This function generates Bob's shared secret from his secret key and Alice's
        public key. It uses a simple but costly loop for traversing the isogeny 
        tree.

        Input: 
        - Bob's secret key SK_Bob, a random number between 1 and oB-1,
        - Alice's public key PK_Alice = [phi_A(x(PB)), phi_A(x(QB)), phi_A(x(QB-PB))].

        Output: 
        - Bob's shared secret: the j-invariant of E_BA.
    """
    
    A = get_A(PK_Alice[0], PK_Alice[1], PK_Alice[2])
    C = 1 # Starting on Alice's Montgomery curve
    
    # Computes R=phi_A(xPB)+SK_Bob*phi_A(xQB) via 3 point ladder
    RX, RZ = LADDER_3_pt(SK_Bob, PK_Alice[0], PK_Alice[1], PK_Alice[2], A, Bob)
    
    isos, mulm = 0, 0
    
    # Bob's main loop
    for e in range(eB-1, -1, -1):
        SX, SZ = xTPLe(RX, RZ, A, C, e); mulm += e # Computes S=[3^e]R
        A, C = get_3_isog(SX, SZ) # Computes the 3-isogeny phi
        RX, RZ = eval_3_isog(SX, SZ, RX, RZ); isos += 1 # R=phi(R)
    
    # Compute the j-invariant of E_BA
    shared_secret_bob = j_inv(A, C)
    
    print "Bob simple secret requires", mulm, "muls-by-3 and", isos, "3-isogenies"
    
    return shared_secret_bob

# Bob shared secret fast
def shared_secret_bob_fast(SK_Bob, PK_Alice, params, splits, MAX):
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
        
    A = get_A(PK_Alice[0], PK_Alice[1], PK_Alice[2])
    C = 1 # Starting on Alice's Montgomery curve
    
    # Computes R=phi_A(xPB)+SK_Bob*phi_A(xQB) via 3 point ladder
    RX, RZ = LADDER_3_pt(SK_Bob, PK_Alice[0], PK_Alice[1], PK_Alice[2], A, Bob)
    
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
    
    # Compute the j-invariant of E_BA
    shared_secret_bob = j_inv(A, C)
    
    print "Bob FAST secret requires", mulm, "muls-by-3 and", isos, "3-isogenies"
    
    return shared_secret_bob
