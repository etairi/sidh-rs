# SIDH in Sage

This folder contains Sage scripts that implement SIDH key exchange including key compression.

In order to run the test script, first of all you need to build and link the scipts using the make command:

> make

Then, you can run the test script with the command

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
