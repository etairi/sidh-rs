# Import Sage
from sage.all import *

"""
    Code to compute optimal strategies for isogeny tree traversal            

    Based on the relative cost ratios of scalar multiplications,      
    optimal strategies are computed by a dynamic programming approach 
    as described in DeFeo, Jao, Plut: "Towards quantum-resistant       
    cryptosystems from supersingular elliptic curve isogenies",        
    J. Math. Crypt., 8(3):209-247, 2014.    
"""

# Turn off arithmetic proof
proof.arithmetic(False)

RR = RealField(10)
Z = IntegerRing()
ZPQ.<P,Q> = PolynomialRing(Z)

nA = 185    # Computing 4^nA-isogenies
pA = 2*12.1 # Linux cost for 2 doublings
qA = 21.6   # Linux cost for 4-isogeny evaluation

nB = 239    # Computing 3^nB-isogenies
pB = 24.3   # Linux cost for tripling
qB = 16.0   # Linux cost for 3-isogeny evaluation

def next_cpq(p, q, Cpq, PQcounts):
    """
        Computes the cost of an optimal strategy for traversing a tree on n leaves
        together with the operation counts in terms of scalar multiplications and 
        isogeny evaluation, given this information for trees on 1 up to n-1 leaves.
        
        Input: 
        - The cost p for a scalar multiplication by \ell,
        - the cost q for the evaluation of an \ell-isogeny,
        - a list Cpq of length n-1 that contains the cost of an optimal strategy 
            for traversal of a tree with i leaves in Cpq[i], and 
        - a list PQcounts of pairs such that the i-th pair contains the number 
            PQcounts[i][1] of \ell-scalar multiplications and the number 
            PQcounts[i][2] of \ell-isogeny evaluations in order to traverse a tree 
            on i leaves using the optimal strategy with cost Cpq[i]. 
        
        Output: 
        - The cost newCpq of an optimal strategy for traversing a tree on n leaves, 
        - the corresponding operation counts newPQcount, and 
        - the splitting newSpq of the n-node strategy into two optimal 
            sub-strategies.
    """

    pgtq = p > q
    n = len(Cpq) + 1 # new index = number of leaves in new strategy
    
    # Compute all possibilities for the cost of a strategy on n leaves by going 
    # through all possible splits into two optimal sub-strategies from the
    # (n-1) strategies provided in PQcounts.
    # Cost = cost of subtree with i leaves + cost of subtree with (n-i) leaves
    #        + cost of (n-i) scalar mults to get to i-subtree root
    #        + cost of i isogeny evaluations to get to (n-i) subtree root 
    newCpqs = [(Cpq[i-1] + Cpq[n-i-1] + (n-i)*p + i*q) for i in [1..(n-1)]]
    
    newCpq = newCpqs[0]
    m = 0
    # Choose the cheapest strategy
    for i in [2..(n-1)]:
        tmpCpq = newCpqs[i-1]
        if newCpq >= tmpCpq:
            # including equality in the condition prefers larger number of isogenies
            newCpq = tmpCpq
            m = i

    # chosen strategy (m-leave sub-tree on the left, (n-m)-subtree on the right)
    newSpq = [m, n-m]
    # updating operation counts
    newPQcount = [PQcounts[m-1][0] + PQcounts[n-m-1][0] + (n-m),
                  PQcounts[m-1][1] + PQcounts[n-m-1][1] + m]

    return newCpq, newSpq, newPQcount

def get_strategies(n, p, q):
    """
        Computes a list of optimal strategies for traversing trees with number of 
        leaves between 1 and n.
        
        Input: 
        - The number n of leaves on the tree,
        - the cost p for scalar multiplication by \ell, and 
        - the cost q for \ell-isogeny evaluation. 
        
        Output:
        - A list Spq of length n containing the splits into two subtrees for all
            optimal strategies on trees with 1<=i<=n leaves.
        - A list PQcounts of length n containing operation counts for the above 
            strategies.
    """

    assert n > 3
    
    # Cost for sub-trees with one leaf (=0) and two leaves (p+q)
    Cpq = [0, p+q]
    # Splits for these sub-trees
    Spq = [[0,0], [1,1]]
    # Operation counts for these sub-trees
    PQcounts = [[0,0], [1,1]]
    
    # Compute in sequence all optimal strategies for trees with 3<=i<=n leaves.
    while True:
        newCpq, newSpq, newPQcount = next_cpq(p, q, Cpq, PQcounts)
        Cpq.append(newCpq)
        Spq.append(newSpq)
        PQcounts.append(newPQcount)

        if len(Cpq) == n:
            break
        
    return Spq, PQcounts

def get_splits(n, Spq):
    """
        Assembles a list of splits by taking the number of leaves in the respective
        right subtrees which is equal to the number of scalar multiplications to 
        reach the root of the next sub-strategy.
        
        Input:
        - The number n of leaves on the tree and
        - the list of splits into two sub-trees as above.
        
        Output:
        - A list of length n describing the splits by giving the number of scalar
            multiplications by \ell to the root of the next subtree.
    """

    return [Spq[i][1] for i in [0..(n-1)]]


# Computing optimal strategies
SpqA, PQcountsA = get_strategies(nA, pA, qA)
print "Top Strategy for A:", SpqA[nA-1]
print PQcountsA[nA-1][0], "MUL-BY-4 and", PQcountsA[nA-1][1], "4-ISO-EVAL ==", PQcountsA[nA-1][0]*pA + PQcountsA[nA-1][1]*qA, "total units"
print "Splits for A:", get_splits(nA, SpqA)

SpqB, PQcountsB = get_strategies(nB, pB, qB)
print "\n\nTop Strategy for B:", SpqB[nB-1]
print PQcountsB[nB-1][0], "MUL-BY-3 and", PQcountsB[nB-1][1], "3-ISO_EVAL ==", PQcountsB[nB-1][0]*pB + PQcountsB[nB-1][1]*qB, "total units"
print "Splits for B:", get_splits(nB, SpqB)
