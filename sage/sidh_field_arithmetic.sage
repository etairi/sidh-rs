# Import Sage and other SIDH related modules
from sage.all import *
from sidh_parameters import *

"""
    Arithmetic file implementing some special field arithmetic functions, such as
    cubing formulas, square roots and arithmetic in the cyclotomic subgroup. 
"""

# Turn off arithmetic proof
proof.arithmetic(False)

# Cubing
def fp2_cub_formula(a):
    """
        This function is for cubing in Fp2. It can be implemented with 2S + 2M 
        and is thus slightly faster than a naive square and multiplication 
        approach (5M), see below. 
    """

    aseq = Fp2(a)
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "aseq" to polynomial, and get the coefficients
    P = aseq.polynomial()
    real, imag = P.coefficients(sparse=False)

    a0 = real
    a1 = imag
    
    return a0*(a0^2-3*a1^2) + j*a1*(3*a0^2-a1^2)

def fp2_cub(a):
    """
        This function is for cubing in Fp2. It uses 2S + 2M and is thus
        slightly faster than a naive square and multiplication approach (5M). 
    """
    
    aseq = Fp2(a)
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "aseq" to polynomial, and get the coefficients
    P = aseq.polynomial()
    real, imag = P.coefficients(sparse=False)

    a0 = real
    a1 = imag
    
    t0 = a0^2
    t1 = a1^2
    c1 = t0 - t1
    t0 = t0 + t0
    t1 = t1 + t1
    c0 = c1 - t1
    c1 = c1 + t0
    c0 = c0 * c0
    c1 = c1 * a1
    
    return c0 + c1*j

# Square roots
def sqrt_fp2(v):
    """
        This function computes square roots (of elements that are square) of
        elements in Fp2 using only Fp arithmetic. Inputs and outputs Fp2 elements
        and makes arbitrary (but deterministic) choice of square root.
    """
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "v" to polynomial, and get the coefficients
    P = v.polynomial()
    real, imag = P.coefficients(sparse=False)

    a = Fp(real)
    b = Fp(imag)
    
    # Fp arithmetic
    t0 = a^2
    t1 = b^2
    t0 = t0 + t1
    t1 = t0^((p + 1) / 4) # 370 squarings, 239 cubes
    t0 = a + t1
    t0 = t0 / 2
    t2 = t0^((p - 3) / 4) # Subchain from inversion
    t1 = t0 * t2
    t2 = t2 * b
    t2 = t2 / 2
    t3 = t1^2
    
    if t3 == t0:
        y = t1 + t2*j # Parsing back into Fp2
    else:
        y = t2 - t1*j # Parsing back into Fp2
    
    return y

def sqrt_fp2_frac(u, v):
    """
        This function computes square roots of elements in (Fp2)^2 using Hamburg's
        trick. Works entirely with Fp arithmetic.
    """
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "u, v" to polynomials, and get the coefficients
    Pu = u.polynomial()
    u_real, u_imag = Pu.coefficients(sparse=False)
    Pv = v.polynomial()
    v_real, v_imag = Pv.coefficients(sparse=False)

    u0 = u_real
    u1 = u_imag
    v0 = v_real
    v1 = v_imag
    
    # Below is all Fp arithmetic
    t0 = v0^2
    t1 = v1^2
    t0 = t0 + t1
    t1 = u0 * v0
    t2 = u1 * v1
    t1 = t1 + t2
    t2 = u1 * v0
    t3 = u0 * v1
    t2 = t2 - t3
    t3 = t1^2
    t4 = t2^2
    t3 = t3 + t4
    t = t3^((p + 1) / 4) # 370 squarings, 239 cubings
    t = t + t1
    t = 2 * t
    t3 = t0^2
    t3 = t3 * t0
    t3 = t3 * t
    t3 = t3^((p - 3) / 4) # Should be in inversion chain
    t3 = t0 * t3
    t1 = t *t3
    y0 = t1 / 2
    y1 = t3 * t2
    t1 = t1^2
    t1 = t1 * t0
    
    if t1 != t:
        temp = y0
        y0 = y1
        y1 = temp
    
    t0 = y0^2
    t1 = y1^2
    t0 = t0 - t1
    t0 = t0 * v0
    t1 = y0 * y1
    t1 = t1 * v1
    t1 = t1 + t1
    t0 = t0 - t1
    
    if t0 != u0:
        y1 = -y1
    
    return y0 + y1*j # Parse back into Fp2

# Almost Montgomery inversion (base field)

# Helper functions
def is_even(n):
    return n%2 == 0

# Notation following Savas-Koc
def moninv_phasei(a, p):
    u = p
    v = a
    r = 0
    s = 1
    k = 0
    
    while v > 0:
        if is_even(u):
            u = u >> 1
            s = 2 * s
        elif is_even(v):
            v = v >> 1
            r = 2 * r
        elif u > v:
            u = (u - v) >> 1
            r = r + s
            s = 2 * s
        elif v >= u:
            v = (v - u) >> 1
            s = s + r
            r = 2 * r
        k += 1
    
    if r >= p:
        r -= p
    
    r = p - r
    
    return r, k

def moninv_phaseii(r, p, k, n):
    for j in [1..(k-n)]:
        if is_even(r):
            r = r >> 1
        else:
            r = (r + p) >> 1
    
    return r

def moninv(a, p, n):
    r, k = moninv_phasei(a, p)
    x = moninv_phaseii(r, p, k, n)
    
    return x

# Montgomery inversion (quadratic extension field)
def fp2_inv(a, p, n):
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "a" to polynomial, and get the coefficients
    P = a.polynomial()
    real, imag = P.coefficients(sparse=False)

    a0 = real
    a1 = imag
    
    num = a0 - j*a1
    den = a0^2 + a1^2
    den = GF(p)(moninv(ZZ(den), p, n))
    
    return num * den

# n-way simultaneous inversion using Montgomery's trick
def mont_n_way_inv(vec, n):
    a = [Fp2(0) for j in [0..n-1]] # Initialize vector of lenght n
    
    a[0] = vec[0]
    for j in [1..(n-1)]:
        a[j] = a[j-1] * vec[j]
    
    # NOTE: This sometimes throws ZeroDivisionError?!
    a_inv = 1 / a[n-1]
    
    for j in range(n-1, 0, -1):
        a[j] = a_inv * a[j-1]
        a_inv = a_inv * vec[j]
    
    a[0] = a_inv
    
    return a

# Arithmetic operations in the cyclotomic subgroup of Fp2
def cube_fp2_cycl_formula(a):
    # Cyclotomic cubing on elements of norm 1, using a^(p+1) = 1.
    aseq = Fp2(a)
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "aseq" to polynomial, and get the coefficients
    P = aseq.polynomial()
    real, imag = P.coefficients(sparse=False)

    a0 = real
    a1 = imag
    
    return (a0*(4*a0^2-3)) + j*(a1*(4*a0^2-1))

def cube_fp2_cycl(a):
    aseq = Fp2(a)
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "aseq" to polynomial, and get the coefficients
    P = aseq.polynomial()
    if len(P.coefficients(sparse=False)) == 1 and aseq == 1:
        real, imag = 1, 0
    else:
        real, imag = P.coefficients(sparse=False)
    
    a0 = real
    a1 = imag
    
    t0 = a0 + a0
    t0 = t0^2
    t0 = t0 - 1
    a1 = t0 * a1
    t0 = t0 - 2
    a0 = t0 * a0

    return a0 + j*a1

def inv_fp2_cycl(a):
    # Cyclotomic inversion, a^(p+1) = 1 => a^(-1) = a^p = a0 - i*a1.
    aseq = Fp2(a)
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "aseq" to polynomial, and get the coefficients
    P = aseq.polynomial()
    if len(P.coefficients(sparse=False)) == 1 and aseq == 1:
        real, imag = 1, 0
    else:
        real, imag = P.coefficients(sparse=False)

    a0 = real
    a1 = imag
    
    return a0 - j*a1

def sqr_fp2_cycl_formula(a):
    """
        Cyclotomic squaring on elements of norm 1, using a^(p+1) = 1.
        This uses 2 base field squarings. If base field squaring is not faster
        than base field multiplication, savings are very small.
    """

    aseq = Fp2(a)
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "aseq" to polynomial, and get the coefficients
    P = aseq.polynomial()

    a0 = real
    a1 = imag
    
    return (2*a0^2-1) + j*((a0+a1)^2-1)

def sqr_fp2_cycl(a):
    aseq = Fp2(a)
    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "aseq" to polynomial, and get the coefficients
    P = aseq.polynomial()
    if len(P.coefficients(sparse=False)) == 1:
        real, imag = P.coefficients(sparse=False)[0], 0
    else:
        real, imag = P.coefficients(sparse=False)

    a0 = real
    a1 = imag
    
    t0 = a0 + a1
    t0 = t0^2
    a1 = t0 - 1
    t0 = a0^2
    t0 = t0 + t0
    a0 = t0 - 1
    
    return a0 + j*a1

def exp_fp2_cycl(y, t):
    # Exponentiation y^t via square and multiply in the cyclotomic group
    res = y
    
    if t == 0:
        res = 1
    else:
        seq = t.digits(base=2)
        for i in [2..len(seq)]:
            res = sqr_fp2_cycl(res)
            if seq[len(seq)-i] == 1:
                res = res * y
    
    return res

# Cube test
def is_cube_fp2(u):
    # Function for deciding whether an element in Fp2 is a cube.

    # We cannot call real() and imag() methods directly, as they do not exists in
    # our case, therefore, we convert "u" to polynomial, and get the coefficients
    P = u.polynomial()
    real, imag = P.coefficients(sparse=False)

    u0 = real
    u1 = imag
    
    # Fp arithmetic below
    v0 = u0^2
    v1 = u1^2
    t0 = v0 + v1
    t0 = 1 / t0 # Fp inversion the quick and dirty one with binary Euclid
    v0 = v0 - v1
    v1 = u0 * u1
    v1 = 2 * v1
    v1 = -v1
    v0 = v0 * t0
    v1 = v1 * t0
    
    # Parse back to Fp2 for (cheap) exponentiation
    v = v0 + v1*j
    for e in [1..372]:
        v = sqr_fp2_cycl(v)
    for e in [1..238]:
        v = cube_fp2_cycl(v)
    
    if v == 1:
        assert u^((p^2-1) / 3) == 1
        return True
    else:
        assert not u^((p^2-1) / 3) == 1
        return False
