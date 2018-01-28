# Import Sage and other SIDH related modules
from sage.all import *
from sidh_parameters import *
from sidh_field_arithmetic import *
from sidh_curve_and_isogeny_arithmetic import *
from sidh import *
from sidh_pairings import *
from sidh_pohlig_hellman import *
from sidh_compression import *

"""
    Test file that demonstrates and tests SIDH key exchange without public key 
    compression (function kextest) and with public key compression (function
    kextest_compress).  

    For the 4 stages of SIDH key exchange (i.e. Alice's key generation, Bob's 
    key generation, Alice's shared secret and Bob's shared secret computation),
    the isogeny computation/evaluation can be performed using two different 
    strategies: 
        (1) the slow but simple "scalar-multiplication-based" strategy.
        (2) a fast way to traverse the isogeny tree using an optimal strategy.

    The function kextest can be run using the fast computations (2) only by
    setting the input boolean simple:=false. If one sets "simple = True", then the
    computation is done using the simple algorithm (1) and the fast algorithm (2)
    and the results from both are asserted to be equal.
"""

# Turn off arithmetic proof
proof.arithmetic(False)

# Key exchange testing
def kextest(n, simple):
    for j in [1..n]:
        print "\nIteration", j
        print "===================================================================="
        print "Generating secret keys..."
        SK_Alice = randint(1, (oA // lA) - 1) * lA # Random even number between 1 and oA-1 
        SK_Bob = randint(1, (oB // lB) - 1) * lB # Random even number between 1 and oB-1 
        print "Done with secret keys."
        print "===================================================================="

        print "Generating Alice's public key... (fast algorithm)."
        PK_Alice = keygen_alice_fast(SK_Alice, params_Alice, splits_Alice, MAX_Alice)
        if simple:
            print "Generating Alice's public key... (simple algorithm)."
            PK_Alice_simple = keygen_alice_simple(SK_Alice, params_Alice)
            equal = PK_Alice == PK_Alice_simple
            print "Result from simple key gen equal to result from fast key gen?", equal
            assert equal
        print "\nDone with Alice's public key."
        print "===================================================================="
        
        print "Generating Bob's public key... (fast algorithm)."
        PK_Bob = keygen_bob_fast(SK_Bob, params_Bob, splits_Bob, MAX_Bob)
        if simple:
            print "Generating Bob's public key... (simple algorithm)."
            PK_Bob_simple = keygen_bob_simple(SK_Bob, params_Bob)
            equal = PK_Bob == PK_Bob_simple
            print "Result from simple key gen equal to result from fast key gen?", equal
            assert equal
        print "\nDone with Bob's public key.\n"
        print "===================================================================="

        print "Generating shared secret for Alice... (fast algorithm)."
        secret_Alice = shared_secret_alice_fast(SK_Alice, PK_Bob, params_Alice, splits_Alice, MAX_Alice)
        if simple:
            print "Generating shared secret for Alice... (simple algorithm)."
            secret_Alice_simple = shared_secret_alice_simple(SK_Alice, PK_Bob)
            equal = secret_Alice == secret_Alice_simple
            print "Results from simple and fast algorithms equal?", equal
            assert equal
        print "\nDone with Alice's shared secret computation."
        print "===================================================================="
        
        print "Generating shared secret for Bob... (fast algorithm)."
        secret_Bob = shared_secret_bob_fast(SK_Bob, PK_Alice, params_Bob, splits_Bob, MAX_Bob)
        if simple:
            print "Generating shared secret for Bob... (simple algorithm)."
            secret_Bob_simple = shared_secret_bob_simple(SK_Bob, PK_Alice)
            equal = secret_Bob == secret_Bob_simple
            print "Results from simple and fast algorithms equal?", equal
            assert equal
        print "\nDone with Bob's shared secret computation."
        print "===================================================================="
        print "Shared secrets are equal?", secret_Alice == secret_Bob
        assert secret_Alice == secret_Bob
        print "===================================================================="
            
# Key exchange testing with compression
def kextest_compress(n):
    for j in [1..n]:
        print "\nIteration", j
        print "===================================================================="
        print "Generating secret keys..."
        SK_Alice = randint(1, (oA // lA) - 1) * lA # Random even number between 1 and oA-1 
        SK_Bob = randint(1, (oB // lB) - 1) * lB # Random even number between 1 and oB-1 
        print "Done with secret keys."
        print "===================================================================="
        
        print "Generating Alice's public key (fast algorithm)..."
        PK_Alice = keygen_alice_fast(SK_Alice, params_Alice, splits_Alice, MAX_Alice)
        print "Compressing Alice's public key."
        PK_Alice_comp_0, PK_Alice_comp_1 = compress_3_torsion(PK_Alice)
        print "\nDone with Alice's public key."
        print "===================================================================="
        
        print "Generating Bob's public key (fast algorithm)..."
        PK_Bob = keygen_bob_fast(SK_Bob, params_Bob, splits_Bob, MAX_Bob)
        print "Compressing Bob's public key."
        PK_Bob_comp_0, PK_Bob_comp_1 = compress_2_torsion(PK_Bob)
        print "\nDone with Bob's public key.\n"
        print "===================================================================="
        
        print "Decompressing Bob's public key and generating shared secret for Alice (fast algorithm)..."
        secret_Alice = shared_secret_alice_decompression(SK_Alice, PK_Bob_comp_0, PK_Bob_comp_1, params_Alice, splits_Alice, MAX_Alice)
        print "\nDone with Alice's shared secret computation."
        print "===================================================================="
        
        print "Decompressing Alice's public key and generating shared secret for Bob (fast algorithm)..."
        secret_Bob = shared_secret_bob_decompression(SK_Bob, PK_Alice_comp_0, PK_Alice_comp_1, params_Bob, splits_Bob, MAX_Bob)
        print "\nDone with Bob's shared secret computation."
        
        print "===================================================================="
        print "Shared secrets are equal?", secret_Alice == secret_Bob
        assert secret_Alice == secret_Bob
        print "===================================================================="
    
simple = False
print "===================================================================="
print "===================================================================="
print "=== Testing SIDH ephemeral key exchange ============================"
if simple:
    print "=== Including simple, but slow isogeny tree traversal =============="
else:
    print "=== Only fast isogeny tree traversal via optimal strategy =========="
print "===================================================================="
kextest(10, simple)

print "\n\n"
print "===================================================================="
print "===================================================================="
print "=== Testing SIDH ephemeral key exchange with PK compression ========"
print "=== Only fast isogeny tree traversal via optimal strategy =========="
print "===================================================================="
kextest_compress(10)
