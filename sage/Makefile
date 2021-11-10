all: 								 \
sidh_parameters.py 					 \
sidh_field_arithmetic.py 			 \
sidh_curve_and_isogeny_arithmetic.py \
sidh.py 							 \
sidh_pairings.py 					 \
sidh_pohlig_hellman.py 				 \
sidh_compression.py

clean:
	rm -f *.py *.pyc

sidh_parameters.py: sidh_parameters.sage.py
	mv sidh_parameters.sage.py sidh_parameters.py

sidh_parameters.sage.py: sidh_parameters.sage
	sage --preparse sidh_parameters.sage

sidh_field_arithmetic.py: sidh_field_arithmetic.sage.py
	mv sidh_field_arithmetic.sage.py sidh_field_arithmetic.py

sidh_field_arithmetic.sage.py: sidh_field_arithmetic.sage
	sage --preparse sidh_field_arithmetic.sage

sidh_curve_and_isogeny_arithmetic.py: sidh_curve_and_isogeny_arithmetic.sage.py
	mv sidh_curve_and_isogeny_arithmetic.sage.py sidh_curve_and_isogeny_arithmetic.py

sidh_curve_and_isogeny_arithmetic.sage.py: sidh_curve_and_isogeny_arithmetic.sage
	sage --preparse sidh_curve_and_isogeny_arithmetic.sage

sidh.py: sidh.sage.py
	mv sidh.sage.py sidh.py

sidh.sage.py: sidh.sage
	sage --preparse sidh.sage

sidh_pairings.py: sidh_pairings.sage.py
	mv sidh_pairings.sage.py sidh_pairings.py

sidh_pairings.sage.py: sidh_pairings.sage
	sage --preparse sidh_pairings.sage

sidh_pohlig_hellman.py: sidh_pohlig_hellman.sage.py
	mv sidh_pohlig_hellman.sage.py sidh_pohlig_hellman.py

sidh_pohlig_hellman.sage.py: sidh_pohlig_hellman.sage
	sage --preparse sidh_pohlig_hellman.sage

sidh_compression.py: sidh_compression.sage.py
	mv sidh_compression.sage.py sidh_compression.py

sidh_compression.sage.py: sidh_compression.sage
	sage --preparse sidh_compression.sage
