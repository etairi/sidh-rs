# SIDH in Sage

This folder contains Sage scripts that implement SIDH key exchange including key compression. They are based on the Magma scripts that were previously included inside [Microsoft Research's implementation of SIDH](https://github.com/Microsoft/PQCrypto-SIDH).

In order to run the test script, first of all you need to build and link the scipts using the make command:

> make

Then, you can run the test script with 

> sage test_sidh.sage

which loads all the other files and provides two test functions.

The function

> kextest(n, simple)

will run and test n random instances of SIDH key exchange without public-key
compression. By default the option simple is set to false, which only runs the fast algorithms. Setting it to
true also runs the simple multiplication-based strategy and asserts
that the results obtained in both approaches are equal. Please note that if you set it to true, you need to issue the above make command again before running the test script. The function 

> kextest_compress(n)

will run and test n random instances of SIDH key exchange including public-key
compression.

Running the script 

> sage kummer_weierstrass_equivalence.sage

demonstrates the equivalence of computations on the Kummer variety with those 
on the Weierstrass model. 
Its purpose is to show that our computations give the same result as Sage.
In particular, we work explicitly on the Kummer variety of supersingular
curves, almost entirely in projective space P^1, and using the Montgomery
x-coordinate.

Finally, running the script 

> sage optimal_strategies.sage 

computes an optimal strategy for
traversing the isogeny tree based on the cost ratios of computing an
m-isogeny versus the multiplication-by-m map. It follows the discussion in the
paper and is based on the original method described by De Feo, Jao and Plut:
Towards quantum-resistant cryptosystems from supersingular elliptic curve
isogenies, J. Math. Crypt., 8(3):209-247, 2014.          