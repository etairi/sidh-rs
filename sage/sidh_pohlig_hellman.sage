# Import Sage and other SIDH related modules
from sage.all import *
from sidh_field_arithmetic import *
from sidh_pairings import *

"""
    Implements the Pohlig-Hellman algorithm to compute discrete logarithms in the
    2- and 3-torsion subgroups, respectively. Different sub-routines reflect the
    windowed Pohlig-Hellman approach.  
"""

# Turn off arithmetic proof
proof.arithmetic(False)

# Two torsion
def phn1_2(q, LUT, a):
    u = q
    alpha_i = 0
    for l in [0..a-2]:
        v = u
        for h in [1..a-1-l]:
            v = sqr_fp2_cycl(v)
        
        if v != 1:
            alpha_i += 2^l
            tmp = LUT[6-a+l]
            u = u * tmp
    
    if u != 1:
        alpha_i += 2^(a-1)
    
    return alpha_i

def phn5_2(q, LUT, LUT_1):
    u = q
    alpha_k = 0
    for ii in [0..3]:
        v = u
        v = sqr_fp2_cycl(v)
        for j in [1..5*(3-ii)]:
            v = sqr_fp2_cycl(v)
        
        alpha_i = phn1_2(v, LUT, 5) # u order 5
        
        alpha_k += alpha_i * (2^(5*ii))
        tmp = exp_fp2_cycl(LUT_1[ii], alpha_i)
        u *= tmp
    # Do the last part
    if u != 1: # u order 2
        alpha_k += 2^(20)
    
    return alpha_k

def phn21_2(q, LUT, LUT_0, LUT_1):
    u = q
    alpha_k = 0
    for ii in [0..2]:
        v = u
        for j in [1..21*(3-ii)]:
            v = sqr_fp2_cycl(v)
        
        alpha_i = phn5_2(v, LUT, LUT_1) # u order 21
        
        alpha_k += alpha_i * (2^(21*ii))
        tmp = exp_fp2_cycl(LUT_0[ii], alpha_i)
        u *= tmp
    
    alpha_i = phn5_2(u, LUT, LUT_1) # u order 21
    alpha_k += alpha_i * (2^63)
    
    return alpha_k

def phn84_2(r, t_ori, LUT, LUT_0, LUT_1, LUT_3):
    alpha = 0
    t = r
    for k in [0..3]:
        u = t
        for ii in [1..36]:
            u = sqr_fp2_cycl(u)
        for ii in [1..84*(3-k)]:
            u = sqr_fp2_cycl(u)
        
        alpha_k = phn21_2(u, LUT, LUT_0, LUT_1) # q order 2^84
        
        alpha += 2^(84*k) * alpha_k
        tmp = exp_fp2_cycl(t_ori[k], alpha_k)
        t *= tmp
    # Do the last part
    for ii in [0..4]:
        u = t
        for j in [1..6*(5-ii)]:
            u = sqr_fp2_cycl(u)
        
        alpha_i = phn1_2(u, LUT, 6) # u order 2^6
        
        alpha += alpha_i * (2^(336+6*ii))
        tmp = exp_fp2_cycl(LUT_3[ii], alpha_i)
        t *= tmp
    
    alpha_i = phn1_2(t, LUT, 6) # u order 2^6
    alpha += alpha_i * (2^(366))
    
    return alpha

def build_LUTs_2(g):
    # Build (small) tables
    tmp = g
    tmp = inv_fp2_cycl(tmp)
    t_ori = [tmp] # order 2^372
    for ii in [1..3]:
        for j in [1..84]:
            tmp = sqr_fp2_cycl(tmp)
        t_ori.append(tmp) # order 2^288 & 2^204 & 2^120
        
    for ii in [1..36]:
        tmp = sqr_fp2_cycl(tmp)
    t_ori.append(tmp) # order 2^84
    
    LUT_0 = [tmp] # order 2^84
    for ii in [1..2]:
        for j in [1..21]:
            tmp = sqr_fp2_cycl(tmp)
        LUT_0.append(tmp) # order 2^63 & 2^42
    for j in [1..6]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_3 = [tmp] # order 2^36
    for j in [1..6]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_3.append(tmp) # order 2^30
    for j in [1..6]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_3.append(tmp) # order 2^24
    for j in [1..3]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_0.append(tmp) # order 2^21
    
    LUT_1 = [LUT_0[3]] # order 2^21
    for ii in [1..3]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_3.append(tmp) # order 2^18
    for ii in [1..2]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_1.append(tmp) # order 2^16
    for j in [1..4]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_3.append(tmp) # order 2^12
    tmp = sqr_fp2_cycl(tmp)
    LUT_1.append(tmp) # order 2^11
    for j in [1..5]:
        tmp = sqr_fp2_cycl(tmp)
    LUT_1.append(tmp) # order 2^16 & 2^11 & 2^6
    LUT_3.append(tmp)
    
    LUT = [LUT_3[5]]
    for ii in [1..4]:
        LUT.append(sqr_fp2_cycl(LUT[ii-1])) # order 2^5 -- 2^1
        
    return t_ori, LUT, LUT_0, LUT_1, LUT_3

def ph_2(phiP, phiQ, PS, QS, A):
    eqp, r0, t0, r1, t1 = tate_pairings_2_torsion(QS, PS, phiP, phiQ, A)
    
    # n = [84,36,21,0,5,1,0,0,6,0]
    
    t_ori, LUT, LUT_0, LUT_1, LUT_3 = build_LUTs_2(eqp)
    
    # Finish computation
    a0 = phn84_2(r0, t_ori, LUT, LUT_0, LUT_1, LUT_3)
    b0 = phn84_2(r1, t_ori, LUT, LUT_0, LUT_1, LUT_3)
    b0 = 2^372 - b0
    a1 = phn84_2(t0, t_ori, LUT, LUT_0, LUT_1, LUT_3)
    b1 = phn84_2(t1, t_ori, LUT, LUT_0, LUT_1, LUT_3)
    b1 = 2^372 - b1
    
    return a0, b0, a1, b1

# Three torsion
def phn1_3(q, LUT, a):
    u = q
    alpha_i = 0

    for l in [0..a-2]:
        v = u
        for h in [1..a-1-l]:
            v = cube_fp2_cycl(v)
        
        if v == LUT[3]:
            alpha_i += 3^l
            tmp = LUT[3-a+l]
            u = u * tmp
        else:
            if not v == 1:
                alpha_i += 2*3^l
                tmp = LUT[3-a+l]^2
                u = u * tmp
    if u == LUT[3]:
        alpha_i += 3^(a-1)
    else:
        if not u == 1:
            alpha_i += 2*3^(a-1)

    return alpha_i

def phn3_3(q, LUT, LUT_1):
    u = q
    alpha = 0
    for i in [0..3]:
        v = u
        for j in [1..3*(4-i)]:
            v = cube_fp2_cycl(v)
        
        alpha_i = phn1_3(v, LUT, 3) # order 3^3
        alpha += alpha_i * (3^(3*i))
        tmp = exp_fp2_cycl(LUT_1[i], alpha_i)
        u *= tmp
    
    alpha_i = phn1_3(u, LUT, 3) # q order 3^3
    alpha += alpha_i * (3^12)
    
    return alpha

def phn15_l_3(q, LUT, LUT_0, LUT_1):
    u = q
    alpha = 0
    for i in [0..2]:
        v = u
        for j in [1..11]:
            v = cube_fp2_cycl(v)
        for j in [1..15*(2-i)]:
            v = cube_fp2_cycl(v)
        
        alpha_i = phn3_3(v, LUT, LUT_1) # u order 3^15
        alpha += alpha_i * (3^(15*i))
        v = LUT_0[i]
        
        for j in [1..5]:
            v = cube_fp2_cycl(v)
        
        tmp = exp_fp2_cycl(v, alpha_i)
        u *= tmp
    
    # Do the last part
    alpha_n = 0
    for i in [0..2]:
        v = u
        for j in [1..2]:
            v = cube_fp2_cycl(v)
        for j in [1..3*(2-i)]:
            v = cube_fp2_cycl(v)
        
        alpha_i = phn1_3(v, LUT, 3) # u order 3^3
        alpha_n += alpha_i * (3^(3*i))
        
        v = LUT_1[i]
        for j in [1..4]:
            v = cube_fp2_cycl(v)
        
        tmp = exp_fp2_cycl(v, alpha_i)
        u *= tmp
    
    # And the final part
    alpha_i = phn1_3(u, LUT, 2) # q order 3^2
    alpha_n += alpha_i * (3^9)
    alpha += alpha_n * (3^45)
    
    return alpha

def phn15_3(q, LUT, LUT_0, LUT_1):
    u = q
    alpha = 0
    for i in [0..2]:
        v = u
        v = cube_fp2_cycl(v)
        for j in [1..15*(3-i)]:
            v = cube_fp2_cycl(v)
        
        alpha_i = phn3_3(v, LUT, LUT_1) # u order 3^15
        alpha += alpha_i * (3^(15*i))
        tmp = exp_fp2_cycl(LUT_0[i], alpha_i)
        u *= tmp
    
    v = u
    v = cube_fp2_cycl(v)
    alpha_i = phn3_3(v, LUT, LUT_1) # u order 3^15
    alpha += alpha_i * (3^(45))
    tmp = exp_fp2_cycl(LUT_0[3], alpha_i)
    u *= tmp
    
    # Do the last part
    if u == LUT[3]:
        alpha += 3^(60)
    else:
        if not u == 1:
            alpha += 2*3^(60)
    
    return alpha

def phn61_3(r, t_ori, LUT, LUT_0, LUT_1):
    alpha = 0
    
    # Start the main loop
    u = r
    for k in [0..2]:
        v = u
        for i in [1..56]:
            v = cube_fp2_cycl(v)
        for i in [1..61*(2-k)]:
            v = cube_fp2_cycl(v)
        
        alpha_k = phn15_3(v, LUT, LUT_0, LUT_1) # q order 3^61
        alpha += 3^(61*k) * alpha_k
        tmp = exp_fp2_cycl(t_ori[k], alpha_k)
        u *= tmp
    
    alpha_n = phn15_l_3(u, LUT, LUT_0, LUT_1) # t order 3^56
    alpha += alpha_n * 3^(183)
    
    return alpha

def build_LUTs_3(g):
    # Build (small) tables
    tmp = g
    tmp = inv_fp2_cycl(tmp)
    t_ori = [tmp] # g order 3^239
    for i in [1..2]:
        for j in [1..61]:
            tmp = cube_fp2_cycl(tmp)
        t_ori.append(tmp) # order 3^178 & 3^117
    for i in [1..56]:
        tmp = cube_fp2_cycl(tmp)
    t_ori.append(tmp) # order 3^61
    LUT_0 = [tmp]
    for i in [1..5]:
        tmp = cube_fp2_cycl(tmp)
    t_ori.append(tmp) # order 3^56
    for i in [1..10]:
        tmp = cube_fp2_cycl(tmp)
    LUT_0.append(tmp)
    for i in [2..3]:
        for j in [1..15]:
            tmp = cube_fp2_cycl(tmp)
        LUT_0.append(tmp) # order 3^61 & 3^46 & 3^31 & 3^16
    tmp = cube_fp2_cycl(tmp)
    LUT_1 = [tmp]
    for i in [1..4]:
        for j in [1..3]:
            tmp = cube_fp2_cycl(tmp)
        LUT_1.append(tmp) # order 3^15 & 3^12 -- 3^3
    LUT = [tmp]
    for i in [1..2]:
        LUT.append(cube_fp2_cycl(LUT[i-1])) # order 3^2 & 3
    LUT.append(inv_fp2_cycl(LUT[2])) # Invert last element back for comparisons in phn functions
    
    return t_ori, LUT, LUT_0, LUT_1

def ph_3(phiP, phiQ, PS, QS, A):
    eqp, r0, t0, r1, t1 = tate_pairings_3_torsion_triple(QS, PS, phiP, phiQ, A)
    # n = [61,56,15,1,3,0,0,0,15,11,3,2]
    
    t_ori, LUT, LUT_0, LUT_1 = build_LUTs_3(eqp)
    
    a0 = phn61_3(r0, t_ori, LUT, LUT_0, LUT_1)
    b0 = phn61_3(r1, t_ori, LUT, LUT_0, LUT_1)
    b0 = 3^239 - b0
    a1 = phn61_3(t0, t_ori, LUT, LUT_0, LUT_1)
    b1 = phn61_3(t1, t_ori, LUT, LUT_0, LUT_1)
    b1 = 3^239 - b1
    
    return a0, b0, a1, b1
