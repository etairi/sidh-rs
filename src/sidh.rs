// Implemention of (ephemeral) supersingular isogeny Diffie-Hellman, as described
// in Costello-Longa-Naehrig 2016. The field arithmetic implementation is 
// mostly based on their implementation.
//
// This package follows their naming convention, writing "Alice" for the party
// using 2^e-isogenies, and "Bob" for the party using 3^e-isogenies.
//
// This package does NOT implement SIDH key validation, so it should only be
// used for ephemeral DH. Each keypair should be used at most once.
//
use ::field::{Fp751Element, ExtensionFieldElement};
use ::curve::{ProjectiveCurveParameters, ProjectivePoint};
use ::isogeny::*;
use ::constants::*;

use core::fmt::Debug;

use rand::{Rng, thread_rng};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen, QuickCheck};

// Macro to assign tuples, as Rust does not allow tuples as lvalue.
macro_rules! assign{
    {($v1:ident, $v2:ident) = $e:expr} =>
    {
        {
            let (v1, v2) = $e;
            $v1 = v1;
            $v2 = v2;
        }
    };
}

// The secret key size, in bytes.
const SECRET_KEY_SIZE: usize = 48;
// The public key size, in bytes.
const PUBLIC_KEY_SIZE: usize = 564;
// The shared secret size, in bytes.
const SHARED_SECRET_SIZE: usize = 188;

// Alice's isogeny strategy.
const MAX_ALICE: usize = 185;
const ALICE_ISOGENY_STRATEGY: [u8; MAX_ALICE] = [0, 1, 1, 2, 2, 2, 3, 4, 4, 4, 4, 5, 5,
	        6, 7, 8, 8, 9, 9, 9, 9, 9, 9, 9, 12, 11, 12, 12, 13, 14, 15, 16, 16, 16, 16,
	        16, 16, 17, 17, 18, 18, 17, 21, 17, 18, 21, 20, 21, 21, 21, 21, 21, 22, 25, 25,
	        25, 26, 27, 28, 28, 29, 30, 31, 32, 32, 32, 32, 32, 32, 32, 33, 33, 33, 35, 36,
	        36, 33, 36, 35, 36, 36, 35, 36, 36, 37, 38, 38, 39, 40, 41, 42, 38, 39, 40, 41,
	        42, 40, 46, 42, 43, 46, 46, 46, 46, 48, 48, 48, 48, 49, 49, 48, 53, 54, 51, 52,
	        53, 54, 55, 56, 57, 58, 59, 59, 60, 62, 62, 63, 64, 64, 64, 64, 64, 64, 64, 64,
	        65, 65, 65, 65, 65, 66, 67, 65, 66, 67, 66, 69, 70, 66, 67, 66, 69, 70, 69, 70,
	        70, 71, 72, 71, 72, 72, 74, 74, 75, 72, 72, 74, 74, 75, 72, 72, 74, 75, 75, 72,
	        72, 74, 75, 75, 77, 77, 79, 80, 80, 82];

// Bob's isogeny strategy.
const MAX_BOB: usize = 239;
const BOB_ISOGENY_STRATEGY: [u8; MAX_BOB] = [0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 6,
	        7, 8, 8, 8, 8, 9, 9, 9, 9, 9, 10, 12, 12, 12, 12, 12, 12, 13, 14, 14, 15, 16,
	        16, 16, 16, 16, 17, 16, 16, 17, 19, 19, 20, 21, 22, 22, 22, 22, 22, 22, 22, 22,
	        22, 22, 24, 24, 25, 27, 27, 28, 28, 29, 28, 29, 28, 28, 28, 30, 28, 28, 28, 29,
	        30, 33, 33, 33, 33, 34, 35, 37, 37, 37, 37, 38, 38, 37, 38, 38, 38, 38, 38, 39,
	        43, 38, 38, 38, 38, 43, 40, 41, 42, 43, 48, 45, 46, 47, 47, 48, 49, 49, 49, 50,
	        51, 50, 49, 49, 49, 49, 51, 49, 53, 50, 51, 50, 51, 51, 51, 52, 55, 55, 55, 56,
	        56, 56, 56, 56, 58, 58, 61, 61, 61, 63, 63, 63, 64, 65, 65, 65, 65, 66, 66, 65,
	        65, 66, 66, 66, 66, 66, 66, 66, 71, 66, 73, 66, 66, 71, 66, 73, 66, 66, 71, 66,
	        73, 68, 68, 71, 71, 73, 73, 73, 75, 75, 78, 78, 78, 80, 80, 80, 81, 81, 82, 83,
	        84, 85, 86, 86, 86, 86, 86, 87, 86, 88, 86, 86, 86, 86, 88, 86, 88, 86, 86, 86,
	        88, 88, 86, 86, 86, 93, 90, 90, 92, 92, 92, 93, 93, 93, 93, 93, 97, 97, 97, 97,
	        97, 97];

// Alice's public key.
#[derive(Copy, Clone)]
pub struct SIDHPublicKeyAlice {
    pub affine_xP  : ExtensionFieldElement,
    pub affine_xQ  : ExtensionFieldElement,
    pub affine_xQmP: ExtensionFieldElement,
}

impl SIDHPublicKeyAlice {
    // Read a public key from a byte slice. The input must be at least 564 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> SIDHPublicKeyAlice {
        assert!(bytes.len() >= 564, "Too short input to SIDH public key from_bytes, expected 564 bytes");
        let affine_xP = ExtensionFieldElement::from_bytes(&bytes[0..188]);
        let affine_xQ = ExtensionFieldElement::from_bytes(&bytes[188..376]);
        let affine_xQmP = ExtensionFieldElement::from_bytes(&bytes[376..564]);
        SIDHPublicKeyAlice{ affine_xP, affine_xQ, affine_xQmP }
    }
    // Write a public key to a byte slice. The output will be 564 bytes long.
    pub fn to_bytes(&self) -> [u8; 564] {
        let mut bytes = [0u8; 564];
        bytes[0..188].clone_from_slice(&self.affine_xP.to_bytes());
        bytes[188..376].clone_from_slice(&self.affine_xQ.to_bytes());
        bytes[376..564].clone_from_slice(&self.affine_xQmP.to_bytes());
        bytes
    }
}

// Bob's public key.
#[derive(Copy, Clone)]
pub struct SIDHPublicKeyBob {
    pub affine_xP  : ExtensionFieldElement,
    pub affine_xQ  : ExtensionFieldElement,
    pub affine_xQmP: ExtensionFieldElement,
}

impl SIDHPublicKeyBob {
    // Read a public key from a byte slice. The input must be at least 564 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> SIDHPublicKeyBob {
        assert!(bytes.len() >= 564, "Too short input to SIDH public key from_bytes, expected 564 bytes");
        let affine_xP = ExtensionFieldElement::from_bytes(&bytes[0..188]);
        let affine_xQ = ExtensionFieldElement::from_bytes(&bytes[188..376]);
        let affine_xQmP = ExtensionFieldElement::from_bytes(&bytes[376..564]);
        SIDHPublicKeyBob{ affine_xP, affine_xQ, affine_xQmP }
    }
    // Write a public key to a byte slice. The output will be 564 bytes long.
    pub fn to_bytes(&self) -> [u8; 564] {
        let mut bytes = [0u8; 564];
        bytes[0..188].clone_from_slice(&self.affine_xP.to_bytes());
        bytes[188..376].clone_from_slice(&self.affine_xQ.to_bytes());
        bytes[376..564].clone_from_slice(&self.affine_xQmP.to_bytes());
        bytes
    }
}

// Alice's secret key.
#[derive(Copy, Clone)]
pub struct SIDHSecretKeyAlice {
    pub scalar: [u8; SECRET_KEY_SIZE],
}

impl Debug for SIDHSecretKeyAlice {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "SIDHSecretKeyAlice(scalar: {:?})", &self.scalar[..])
    }
}

#[cfg(test)]
impl Arbitrary for SIDHSecretKeyAlice {
    fn arbitrary<G: Gen>(_g: &mut G) -> SIDHSecretKeyAlice {
        let mut rng = thread_rng();
        let (_, alice_secret_key) = generate_alice_keypair(&mut rng);
        alice_secret_key
    }
}

impl SIDHSecretKeyAlice {
    // Compute the corresponding public key for the given secret key.
    pub fn public_key(&self) -> SIDHPublicKeyAlice {
        let mut xP = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PB);  // = ( x_P : 1) = x(P_B)
        let mut xQ = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PB);  //
        xQ.X = -(&xQ.X);                                                      // = (-x_P : 1) = x(Q_B)
        let mut xQmP = ProjectivePoint::distort_and_difference(&AFFINE_X_PB); // = x(Q_B - P_B)

        let mut xR = ProjectivePoint::secret_point(&AFFINE_X_PA, &AFFINE_Y_PA, &self.scalar[..]);

        // Starting curve has a = 0, so (A:C) = (0,1).
        let current_curve = ProjectiveCurveParameters{ A: ExtensionFieldElement::zero(), C: ExtensionFieldElement::one() }; 
        let (mut current_curve, firstPhi) = FirstFourIsogeny::compute_first_four_isogeny(&current_curve);

        xP = firstPhi.eval(&xP);
        xQ = firstPhi.eval(&xQ);
        xQmP = firstPhi.eval(&xQmP);
        xR = firstPhi.eval(&xR);
        
        // NOTE: One cannot use a Rust slice to insert, append or remove elements from 
        //       the underlying container, therefore, we use Vec.
        let mut points: Vec<ProjectivePoint> = Vec::with_capacity(8);
        let mut indices: Vec<usize> = Vec::with_capacity(8);
        let mut i: usize = 0;
        let mut phi: FourIsogeny;
        for j in 1..185 {
            while i < 185-j {
                points.push(xR);
                indices.push(i);
                let k = ALICE_ISOGENY_STRATEGY[185-i-j];
                xR = xR.pow2k(&current_curve, (2*k) as u32);
                i = i + k as usize;
            }
            assign!{(current_curve, phi) = FourIsogeny::compute_four_isogeny(&xR)};

            for k in 0..points.len() {
                points[k] = phi.eval(&points[k]);
            }

            xP = phi.eval(&xP);
            xQ = phi.eval(&xQ);
            xQmP = phi.eval(&xQmP);

            // Pop xR from pointsm and i from indices.
            xR = points.pop().unwrap();
            i = indices.pop().unwrap();
        }

        assign!{(current_curve, phi) = FourIsogeny::compute_four_isogeny(&xR)};

        xP = phi.eval(&xP);
        xQ = phi.eval(&xQ);
        xQmP = phi.eval(&xQmP);

        let (invZP, invZQ, invZQmP) = ExtensionFieldElement::batch3_inv(&xP.Z, &xQ.Z, &xQmP.Z);
        let affine_xP = &xP.X * &invZP;
        let affine_xQ = &xQ.X * &invZQ;
        let affine_xQmP = &xQmP.X * &invZQmP;

        SIDHPublicKeyAlice{ affine_xP, affine_xQ, affine_xQmP }
    }
    // Compute (Alice's view of) a shared secret using Alice's secret key and Bob's public key.
    pub fn shared_secret(&self, bob_public: &SIDHPublicKeyBob) -> [u8; SHARED_SECRET_SIZE] {
        let current_curve = ProjectiveCurveParameters::recover_curve_parameters(&bob_public.affine_xP, &bob_public.affine_xQ, &bob_public.affine_xQmP);
        let xP = ProjectivePoint::from_affine(&bob_public.affine_xP);
        let xQ = ProjectivePoint::from_affine(&bob_public.affine_xQ);
        let xQmP = ProjectivePoint::from_affine(&bob_public.affine_xQmP);
        let mut xR = ProjectivePoint::right_to_left_ladder(&xP, &xQ, &xQmP, &current_curve, &self.scalar[..]);

        let (mut current_curve, firstPhi) = FirstFourIsogeny::compute_first_four_isogeny(&current_curve);
        xR = firstPhi.eval(&xR);

        // NOTE: One cannot use a Rust slice to insert, append or remove elements from 
        //       the underlying container, therefore, we use Vec.
        let mut points: Vec<ProjectivePoint> = Vec::with_capacity(8);
        let mut indices: Vec<usize> = Vec::with_capacity(8);
        let mut i: usize = 0;
        let mut phi: FourIsogeny;
        for j in 1..185 {
            while i < 185-j {
                points.push(xR);
                indices.push(i);
                let k = ALICE_ISOGENY_STRATEGY[185-i-j];
                xR = xR.pow2k(&current_curve, (2*k) as u32);
                i = i + k as usize;
            }
            assign!{(current_curve, phi) = FourIsogeny::compute_four_isogeny(&xR)};

            for k in 0..points.len() {
                points[k] = phi.eval(&points[k]);
            }

            // Pop xR from pointsm and i from indices.
		    xR = points.pop().unwrap();
            i = indices.pop().unwrap();
        }

        assign!{(current_curve, phi) = FourIsogeny::compute_four_isogeny(&xR)};

        let j_inv = current_curve.j_invariant();
        let shared_secret = j_inv.to_bytes();
        shared_secret
    }
}

// Bob's secret key.
#[derive(Copy, Clone)]
pub struct SIDHSecretKeyBob {
    pub scalar: [u8; SECRET_KEY_SIZE],
}

impl Debug for SIDHSecretKeyBob {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "SIDHSecretKeyBob(scalar: {:?})", &self.scalar[..])
    }
}

#[cfg(test)]
impl Arbitrary for SIDHSecretKeyBob {
    fn arbitrary<G: Gen>(_g: &mut G) -> SIDHSecretKeyBob {
        let mut rng = thread_rng();
        let (_, bob_secret_key) = generate_bob_keypair(&mut rng);
        bob_secret_key
    }
}

impl SIDHSecretKeyBob {
    // Compute the public key corresponding to the secret key.
    pub fn public_key(&self) -> SIDHPublicKeyBob {
        let mut xP = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PA);  // = ( x_P : 1) = x(P_A)
        let mut xQ = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PA);  //
        xQ.X = -(&xQ.X);                                                      // = (-x_P : 1) = x(Q_A)
        let mut xQmP = ProjectivePoint::distort_and_difference(&AFFINE_X_PA); // = x(Q_B - P_B)

        let mut xR = ProjectivePoint::secret_point(&AFFINE_X_PB, &AFFINE_Y_PB, &self.scalar[..]);

        // Starting curve has a = 0, so (A:C) = (0,1).
        let mut current_curve = ProjectiveCurveParameters{ A: ExtensionFieldElement::zero(), C: ExtensionFieldElement::one() };

        // NOTE: One cannot use a Rust slice to insert, append or remove elements from 
        //       the underlying container, therefore, we use Vec.
        let mut points: Vec<ProjectivePoint> = Vec::with_capacity(8);
        let mut indices: Vec<usize> = Vec::with_capacity(8);
        let mut i: usize = 0;
        let mut phi: ThreeIsogeny;
        for j in 1..239 {
            while i < 239-j {
                points.push(xR);
                indices.push(i);
                let k = BOB_ISOGENY_STRATEGY[239-i-j];
                xR = xR.pow3k(&current_curve, k as u32);
                i = i + k as usize;
            }
             assign!{(current_curve, phi) = ThreeIsogeny::compute_three_isogeny(&xR)};

            for k in 0..points.len() {
                points[k] = phi.eval(&points[k]);
            }

            xP = phi.eval(&xP);
            xQ = phi.eval(&xQ);
            xQmP = phi.eval(&xQmP);

            // Pop xR from points and i from indices.
		    xR = points.pop().unwrap();
            i = indices.pop().unwrap();
        }

        assign!{(current_curve, phi) = ThreeIsogeny::compute_three_isogeny(&xR)};

        xP = phi.eval(&xP);
        xQ = phi.eval(&xQ);
        xQmP = phi.eval(&xQmP);

        let (invZP, invZQ, invZQmP) = ExtensionFieldElement::batch3_inv(&xP.Z, &xQ.Z, &xQmP.Z);
        let affine_xP = &xP.X * &invZP;
        let affine_xQ = &xQ.X * &invZQ;
        let affine_xQmP = &xQmP.X * &invZQmP;

        SIDHPublicKeyBob{ affine_xP, affine_xQ, affine_xQmP }
    }
    // Compute (Bob's view of) a shared secret using Bob's secret key and Alice's public key.
    pub fn shared_secret(&self, alice_public: &SIDHPublicKeyAlice) -> [u8; SHARED_SECRET_SIZE] {
        let mut current_curve = ProjectiveCurveParameters::recover_curve_parameters(&alice_public.affine_xP, &alice_public.affine_xQ, &alice_public.affine_xQmP);
        let xP = ProjectivePoint::from_affine(&alice_public.affine_xP);
        let xQ = ProjectivePoint::from_affine(&alice_public.affine_xQ);
        let xQmP = ProjectivePoint::from_affine(&alice_public.affine_xQmP);
        let mut xR = ProjectivePoint::right_to_left_ladder(&xP, &xQ, &xQmP, &current_curve, &self.scalar[..]);

        // NOTE: One cannot use a Rust slice to insert, append or remove elements from 
        //       the underlying container, therefore, we use Vec.
        let mut points: Vec<ProjectivePoint> = Vec::with_capacity(8);
        let mut indices: Vec<usize> = Vec::with_capacity(8);
        let mut i: usize = 0;
        let mut phi: ThreeIsogeny;
        for j in 1..239 {
            while i < 239-j {
                points.push(xR);
                indices.push(i);
                let k = BOB_ISOGENY_STRATEGY[239-i-j];
                xR = xR.pow3k(&current_curve, k as u32);
                i = i + k as usize;
            }
            assign!{(current_curve, phi) = ThreeIsogeny::compute_three_isogeny(&xR)};

            for k in 0..points.len() {
                points[k] = phi.eval(&points[k]);
            }

            // Pop xR from points and i from indices.
		    xR = points.pop().unwrap();
            i = indices.pop().unwrap();
        }

        assign!{(current_curve, phi) = ThreeIsogeny::compute_three_isogeny(&xR)};

        let j_inv = current_curve.j_invariant();
        let shared_secret = j_inv.to_bytes();
        shared_secret
    }
}

// Generate a keypair for "Alice". Note that because this library does not
// implement SIDH validation, each keypair should be used for at most one
// shared secret computation.
pub fn generate_alice_keypair(rng: &mut Rng) -> (SIDHPublicKeyAlice, SIDHSecretKeyAlice) {
    let mut scalar = [0u8; SECRET_KEY_SIZE];
    rng.fill_bytes(&mut scalar[..]);

    // Bit-twiddle to ensure scalar is in 2*[0,2^371):
    scalar[47] = 0;
    scalar[46] &= 15; // Clear high bits, so scalar < 2^372.
    scalar[0] &= 254; // Clear low bit, so scalar is even.

    // We actually want scalar in 2*(0,2^371), but the above procedure
	// generates 0 with probability 2^(-371), which isn't worth checking
	// for.
    let secret_key = SIDHSecretKeyAlice{ scalar };
    let public_key = secret_key.public_key();

    (public_key, secret_key)
}

// Generate a keypair for "Bob". Note that because this library does not
// implement SIDH validation, each keypair should be used for at most one
// shared secret computation.
pub fn generate_bob_keypair(rng: &mut Rng) -> (SIDHPublicKeyBob, SIDHSecretKeyBob) {
    let mut scalar = [0u8; SECRET_KEY_SIZE];
    // Perform rejection sampling to obtain a random value in [0,3^238]:
    let mut ok: u32 = 1;
    for _ in 0..102 {
        rng.fill_bytes(&mut scalar[..]);
        // Mask the high bits to obtain a uniform value in [0,2^378):
        scalar[47] &= 3;
        // Accept if scalar < 3^238 (this happens with probability ~0.5828).
        unsafe { checklt238_asm(&scalar, &mut ok); }
        if ok == 0 { break; }
    }
    // ok is nonzero if all 102 trials failed.
	// This happens with probability 0.41719...^102 < 2^(-128), i.e., never.
    if ok != 0 { panic!("All 102 trials failed!"); }
    
    // Multiply by 3 to get a scalar in 3*[0,3^238):
    unsafe { mulby3_asm(&mut scalar); }

    // We actually want scalar in 2*(0,2^371), but the above procedure
	// generates 0 with probability 3^(-238), which isn't worth checking
	// for.
    let secret_key = SIDHSecretKeyBob{ scalar };
    let public_key = secret_key.public_key();

    (public_key, secret_key)
}

extern {
    // Set result to zero if the input scalar is <= 3^238.
    #[no_mangle]
    pub fn checklt238_asm(scalar: &[u8; 48], result: &mut u32);
    // Set scalar = 3*scalar.
    #[no_mangle]
    pub fn mulby3_asm(scalar: &mut [u8; 48]);
}

#[cfg(test)]
mod test {
    use super::*;

    // Perform Alice's (2-isogeny) key generation, using the slow but simple multiplication-based strategy.
    //
    // This function just exists to ensure that the fast isogeny-tree strategy works correctly.
    pub fn alice_keygen_slow(secret_key: &SIDHSecretKeyAlice) -> SIDHPublicKeyAlice {
        let mut xP = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PB);  // = ( x_P : 1) = x(P_B)
        let mut xQ = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PB);  //
        xQ.X = -(&xQ.X);                                                      // = (-x_P : 1) = x(Q_B)
        let mut xQmP = ProjectivePoint::distort_and_difference(&AFFINE_X_PB); // = x(Q_B - P_B)

        let mut xR = ProjectivePoint::secret_point(&AFFINE_X_PA, &AFFINE_Y_PA, &secret_key.scalar[..]);
        // Starting curve has a = 0, so (A:C) = (0,1).
        let current_curve = ProjectiveCurveParameters{ A: ExtensionFieldElement::zero(), C: ExtensionFieldElement::one() };

        let (mut current_curve, firstPhi) = FirstFourIsogeny::compute_first_four_isogeny(&current_curve);

        xP = firstPhi.eval(&xP);
        xQ = firstPhi.eval(&xQ);
        xQmP = firstPhi.eval(&xQmP);
        xR = firstPhi.eval(&xR);

        let mut phi: FourIsogeny;
        // rev() makes the loop go from 368 down to 0.
        for e in (0..(372 - 4 + 1)).rev().step_by(2) {
            let xS = xR.pow2k(&current_curve, e as u32);
            assign!{(current_curve, phi) = FourIsogeny::compute_four_isogeny(&xS)};

            xR = phi.eval(&xR);
            xP = phi.eval(&xP);
            xQ = phi.eval(&xQ);
            xQmP = phi.eval(&xQmP);
        }

        let (invZP, invZQ, invZQmP) = ExtensionFieldElement::batch3_inv(&xP.Z, &xQ.Z, &xQmP.Z);
        let affine_xP = &xP.X * &invZP;
        let affine_xQ = &xQ.X * &invZQ;
        let affine_xQmP = &xQmP.X * &invZQmP;

        SIDHPublicKeyAlice{ affine_xP, affine_xQ, affine_xQmP }
    }
    // Perform Bob's (3-isogeny) key generation, using the slow but simple multiplication-based strategy.
    //
    // This function just exists to ensure that the fast isogeny-tree strategy works correctly.
    pub fn bob_keygen_slow(secret_key: &SIDHSecretKeyBob) -> SIDHPublicKeyBob {
        let mut xP = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PA);  // = ( x_P : 1) = x(P_A)
        let mut xQ = ProjectivePoint::from_affine_prime_field(&AFFINE_X_PA);  //
        xQ.X = -(&xQ.X);                                                      // = (-x_P : 1) = x(Q_A)
        let mut xQmP = ProjectivePoint::distort_and_difference(&AFFINE_X_PA); // = x(Q_B - P_B)

        let mut xR = ProjectivePoint::secret_point(&AFFINE_X_PB, &AFFINE_Y_PB, &secret_key.scalar[..]);
        // Starting curve has a = 0, so (A:C) = (0,1).
        let mut current_curve = ProjectiveCurveParameters{ A: ExtensionFieldElement::zero(), C: ExtensionFieldElement::one() };

        let mut phi: ThreeIsogeny;
        // rev() makes the loop go from 238 down to 0.
        for e in (0..239).rev() {
            let xS = xR.pow3k(&current_curve, e as u32);
            assign!{(current_curve, phi) = ThreeIsogeny::compute_three_isogeny(&xS)};

            xR = phi.eval(&xR);
            xP = phi.eval(&xP);
            xQ = phi.eval(&xQ);
            xQmP = phi.eval(&xQmP);
        }

        let (invZP, invZQ, invZQmP) = ExtensionFieldElement::batch3_inv(&xP.Z, &xQ.Z, &xQmP.Z);
        let affine_xP = &xP.X * &invZP;
        let affine_xQ = &xQ.X * &invZQ;
        let affine_xQmP = &xQmP.X * &invZQmP;

        SIDHPublicKeyBob{ affine_xP, affine_xQ, affine_xQmP }
    }
    // Perform Alice's key agreement, using the slow but simple multiplication-based strategy.
    //
    // This function just exists to ensure that the fast isogeny-tree strategy works correctly.
    pub fn alice_shared_secret_slow(bob_public: &SIDHPublicKeyBob, alice_secret: &SIDHSecretKeyAlice) -> [u8; SHARED_SECRET_SIZE] {
        let current_curve = ProjectiveCurveParameters::recover_curve_parameters(&bob_public.affine_xP, &bob_public.affine_xQ, &bob_public.affine_xQmP);
        let xP = ProjectivePoint::from_affine(&bob_public.affine_xP);
        let xQ = ProjectivePoint::from_affine(&bob_public.affine_xQ);
        let xQmP = ProjectivePoint::from_affine(&bob_public.affine_xQmP);
        
        let mut xR = ProjectivePoint::three_point_ladder(&xP, &xQ, &xQmP, &current_curve, &alice_secret.scalar[..]);
        
        let (mut current_curve, firstPhi) = FirstFourIsogeny::compute_first_four_isogeny(&current_curve);
        xR = firstPhi.eval(&xR);

        let mut phi: FourIsogeny;
        // rev() makes the loop go from 368 down to 2.
        for e in (2..(372 - 4 + 1)).rev().step_by(2) {
            let xS = xR.pow2k(&current_curve, e as u32);
            assign!{(current_curve, phi) = FourIsogeny::compute_four_isogeny(&xS)};

            xR = phi.eval(&xR);
        }

        assign!{(current_curve, phi) = FourIsogeny::compute_four_isogeny(&xR)};

        let j_inv = current_curve.j_invariant();
        let shared_secret = j_inv.to_bytes();
        shared_secret
    }
    // Perform Bob's key agreement, using the slow but simple multiplication-based strategy.
    //
    // This function just exists to ensure that the fast isogeny-tree strategy works correctly.
    pub fn bob_shared_secret_slow(alice_public: &SIDHPublicKeyAlice, bob_secret: &SIDHSecretKeyBob) -> [u8; SHARED_SECRET_SIZE] {
        let mut current_curve = ProjectiveCurveParameters::recover_curve_parameters(&alice_public.affine_xP, &alice_public.affine_xQ, &alice_public.affine_xQmP);
        let xP = ProjectivePoint::from_affine(&alice_public.affine_xP);
        let xQ = ProjectivePoint::from_affine(&alice_public.affine_xQ);
        let xQmP = ProjectivePoint::from_affine(&alice_public.affine_xQmP);
        
        let mut xR = ProjectivePoint::three_point_ladder(&xP, &xQ, &xQmP, &current_curve, &bob_secret.scalar[..]);

        let mut phi: ThreeIsogeny;
        // rev() makes the loop go from 239 down to 1.
        for e in (1..239).rev() {
            let xS = xR.pow3k(&current_curve, e as u32);
            assign!{(current_curve, phi) = ThreeIsogeny::compute_three_isogeny(&xS)};

            xR = phi.eval(&xR);
        }

        assign!{(current_curve, phi) = ThreeIsogeny::compute_three_isogeny(&xR)};

        let j_inv = current_curve.j_invariant();
        let shared_secret = j_inv.to_bytes();
        shared_secret
    }

    #[test]
    fn multiply_by_three() {
        // sage: repr((3^238 -1).digits(256))
        let mut three238_minus1: [u8; 48] = [248, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2];
        // sage: repr((3*(3^238 -1)).digits(256))
        let three_times_three238_minus1: [u8; 48] = [232, 142, 138, 135, 159, 84, 104, 201, 62, 110, 199, 124, 63, 161, 177, 89, 169, 109, 135, 190, 110, 125, 134, 233, 132, 128, 116, 37, 203, 69, 80, 43, 86, 104, 198, 173, 123, 249, 9, 41, 225, 192, 113, 31, 84, 93, 254, 6];

        unsafe { mulby3_asm(&mut three238_minus1); }

        assert!(three238_minus1.iter().zip(three_times_three238_minus1.iter()).all(|(a, b)| a == b), 
                "\nExpected\n{:?}\nfound\n{:?}", &three_times_three238_minus1[..], &three238_minus1[..]);
    }

    #[test]
    fn check_less_than_three238() {
        let three238_minus1: [u8; 48] = [248, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2];
        let three238: [u8; 48] = [249, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2];
        let three238_plus1: [u8; 48] = [250, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2];

        let mut result: u32 = 57;

        unsafe { checklt238_asm(&three238_minus1, &mut result); }
        assert_eq!(result, 0, "\nExpected 0, got {}", result);

        unsafe { checklt238_asm(&three238, &mut result); }
        assert_ne!(result, 0, "\nExpected nonzero, got {}", result);

        unsafe { checklt238_asm(&three238_plus1, &mut result); }
        assert_ne!(result, 0, "\nExpected nonzero, got {}", result);
    }

    #[test]
    fn ephemeral_shared_secret() {
        fn shared_secrets_match(alice_secret: SIDHSecretKeyAlice, bob_secret: SIDHSecretKeyBob) -> bool {
            let alice_public = alice_secret.public_key();
            let bob_public = bob_secret.public_key();

            let alice_shared_secret = alice_secret.shared_secret(&bob_public);
            let bob_shared_secret = bob_secret.shared_secret(&alice_public);

            println!("alice_shared_secret: {:?}", &alice_shared_secret[..]);
            println!("bob_shared_secret: {:?}\n", &bob_shared_secret[..]);

            alice_shared_secret.iter().zip(bob_shared_secret.iter()).all(|(a, b)| a == b)
        }
        QuickCheck::new().quickcheck(shared_secrets_match as fn(SIDHSecretKeyAlice, SIDHSecretKeyBob) -> bool);
    }

    #[test]
    fn alice_keygen_fast_vs_slow() {
        // m_A = 2*randint(0,2^371)
        let m_A: [u8; 48] = [248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0];

        let alice_secret_key = SIDHSecretKeyAlice{ scalar: m_A };
        let fast_pubkey = alice_secret_key.public_key();
        let slow_pubkey = alice_keygen_slow(&alice_secret_key);

        assert!(fast_pubkey.affine_xP.vartime_eq(&slow_pubkey.affine_xP), 
                "\nExpected affine_xP = {:?}\nfound {:?}", fast_pubkey.affine_xP, slow_pubkey.affine_xP);
        assert!(fast_pubkey.affine_xQ.vartime_eq(&slow_pubkey.affine_xQ), 
                "\nExpected affine_xQ = {:?}\nfound {:?}", fast_pubkey.affine_xQ, slow_pubkey.affine_xQ);
        assert!(fast_pubkey.affine_xQmP.vartime_eq(&slow_pubkey.affine_xQmP), 
                "\nExpected affine_xQmP = {:?}\nfound {:?}", fast_pubkey.affine_xQmP, slow_pubkey.affine_xQmP);
    }

    #[test]
    fn bob_keygen_fast_vs_slow() {
        // m_B = 3*randint(0,3^238)
        let m_B: [u8; 48] = [246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0];

        let bob_secret_key = SIDHSecretKeyBob{ scalar: m_B };
        let fast_pubkey = bob_secret_key.public_key();
        let slow_pubkey = bob_keygen_slow(&bob_secret_key);

        assert!(fast_pubkey.affine_xP.vartime_eq(&slow_pubkey.affine_xP), 
                "\nExpected affine_xP = {:?}\nfound {:?}", fast_pubkey.affine_xP, slow_pubkey.affine_xP);
        assert!(fast_pubkey.affine_xQ.vartime_eq(&slow_pubkey.affine_xQ), 
                "\nExpected affine_xQ = {:?}\nfound {:?}", fast_pubkey.affine_xQ, slow_pubkey.affine_xQ);
        assert!(fast_pubkey.affine_xQmP.vartime_eq(&slow_pubkey.affine_xQmP), 
                "\nExpected affine_xQmP = {:?}\nfound {:?}", fast_pubkey.affine_xQmP, slow_pubkey.affine_xQmP);
    }

    #[test]
    fn shared_secret() {
        // m_A = 2*randint(0,2^371)
        let m_A: [u8; 48] = [248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0];
        // m_B = 3*randint(0,3^238)
        let m_B: [u8; 48] = [246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0];

        let alice_secret = SIDHSecretKeyAlice{ scalar: m_A };
        let bob_secret = SIDHSecretKeyBob{ scalar: m_B };

        let alice_public = alice_secret.public_key();
        let bob_public = bob_secret.public_key();

        let alice_shared_secret_slow = alice_shared_secret_slow(&bob_public, &alice_secret);
        let alice_sahred_secret_fast = alice_secret.shared_secret(&bob_public);
        let bob_shared_secret_slow = bob_shared_secret_slow(&alice_public, &bob_secret);
        let bob_shared_secret_fast = bob_secret.shared_secret(&alice_public);

        assert!(alice_sahred_secret_fast.iter().zip(bob_shared_secret_fast.iter()).all(|(a, b)| a == b), 
            "\nShared secret (fast) mismatch: Alice has {:?}\nBob has {:?}", &alice_sahred_secret_fast[..], &bob_shared_secret_fast[..]);
        assert!(alice_shared_secret_slow.iter().zip(bob_shared_secret_slow.iter()).all(|(a, b)| a == b), 
            "\nShared secret (slow) mismatch: Alice has {:?}\nBob has {:?}", &alice_shared_secret_slow[..], &bob_shared_secret_slow[..]);
        assert!(alice_shared_secret_slow.iter().zip(bob_shared_secret_fast.iter()).all(|(a, b)| a == b), 
            "\nShared secret mismatch: Alice (slow) has {:?}\nBob (fast) has {:?}", &alice_shared_secret_slow[..], &bob_shared_secret_fast[..]);
    }

    #[test]
    fn secret_point() {
        // m_A = 2*randint(0,2^371)
        let m_A: [u8; 48] = [248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0];
        // m_B = 3*randint(0,3^238)
        let m_B: [u8; 48] = [246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0];

        let xR_A = ProjectivePoint::secret_point(&AFFINE_X_PA, &AFFINE_Y_PA, &m_A[..]);
        let xR_B = ProjectivePoint::secret_point(&AFFINE_X_PB, &AFFINE_Y_PB, &m_B[..]);

        let sage_affine_xR_A = ExtensionFieldElement{ A: Fp751Element([0x29f1dff12103d089, 0x7409b9bf955e0d87, 0xe812441c1cca7288, 0xc32b8b13efba55f9, 0xc3b76a80696d83da, 0x185dd4f93a3dc373, 0xfc07c1a9115b6717, 0x39bfcdd63b5c4254, 0xc4d097d51d41efd8, 0x4f893494389b21c7, 0x373433211d3d0446, 0x53c35ccc3d22]), B: Fp751Element([0x722e718f33e40815, 0x8c5fc0fdf715667, 0x850fd292bbe8c74c, 0x212938a60fcbf5d3, 0xfdb2a099d58dc6e7, 0x232f83ab63c9c205, 0x23eda62fa5543f5e, 0x49b5758855d9d04f, 0x6b455e6642ef25d1, 0x9651162537470202, 0xfeced582f2e96ff0, 0x33a9e0c0dea8]) };
        let sage_affine_xR_B = ExtensionFieldElement{ A: Fp751Element([0xdd4e66076e8499f5, 0xe7efddc6907519da, 0xe31f9955b337108c, 0x8e558c5479ffc5e1, 0xfee963ead776bfc2, 0x33aa04c35846bf15, 0xab77d91b23617a0d, 0xbdd70948746070e2, 0x66f71291c277e942, 0x187c39db2f901fce, 0x69262987d5d32aa2, 0xe1db40057dc]), B: Fp751Element([0xd1b766abcfd5c167, 0x4591059dc8a382fa, 0x1ddf9490736c223d, 0xc96db091bdf2b3dd, 0x7b8b9c3dc292f502, 0xe5b18ad85e4d3e33, 0xc3f3479b6664b931, 0xa4f17865299e21e6, 0x3f7ef5b332fa1c6e, 0x875bedb5dab06119, 0x9b5a06ea2e23b93, 0x43d48296fb26]) };

        let affine_xR_A = xR_A.to_affine();
        assert!(sage_affine_xR_A.vartime_eq(&affine_xR_A), 
                "\nExpected\n{:?}\nfound\n{:?}", sage_affine_xR_A, affine_xR_A);

        let affine_xR_B = xR_B.to_affine();
        assert!(sage_affine_xR_B.vartime_eq(&affine_xR_B), 
                "\nExpected\n{:?}\nfound\n{:?}", sage_affine_xR_B, affine_xR_B);
    }
}

//#[cfg(all(test, feature = "bench"))]
#[cfg(test)]
mod bench {
    use super::*;
    use test::Bencher;

    const SHARED_SECRET_ALICE_PUBLIC: SIDHPublicKeyAlice = SIDHPublicKeyAlice{
        affine_xP: ExtensionFieldElement{ A: Fp751Element([0xea6b2d1e2aebb250, 0x35d0b205dc4f6386, 0xb198e93cb1830b8d, 0x3b5b456b496ddcc6, 0x5be3f0d41132c260, 0xce5f188807516a00, 0x54f3e7469ea8866d, 0x33809ef47f36286, 0x6fa45f83eabe1edb, 0x1b3391ae5d19fd86, 0x1e66daf48584af3f, 0xb430c14aaa87]), B: Fp751Element([0x97b41ebc61dcb2ad, 0x80ead31cb932f641, 0x40a940099948b642, 0x2a22fd16cdc7fe84, 0xaabf35b17579667f, 0x76c1d0139feb4032, 0x71467e1e7b1949be, 0x678ca8dadd0d6d81, 0x14445daea9064c66, 0x92d161eab4fa4691, 0x8dfbb01b6b238d36, 0x2e3718434e4e]) },
        affine_xQ: ExtensionFieldElement{ A: Fp751Element([0xb055cf0ca1943439, 0xa9ff5de2fa6c69ed, 0x4f2761f934e5730a, 0x61a1dcaa1f94aa4b, 0xce3c8fadfd058543, 0xeac432aaa6701b8e, 0x8491d523093aea8b, 0xba273f9bd92b9b7f, 0xd8f59fd34439bb5a, 0xdc0350261c1fe600, 0x99375ab1eb151311, 0x14d175bbdbc5]), B: Fp751Element([0xffb0ef8c2111a107, 0x55ceca3825991829, 0xdbf8a1ccc075d34b, 0xb8e9187bd85d8494, 0x670aa2d5c34a03b0, 0xef9fe2ed2b064953, 0xc911f5311d645aee, 0xf4411f409e410507, 0x934a0a852d03e1a8, 0xe6274e67ae1ad544, 0x9f4bc563c69a87bc, 0x6f316019681e]) },
        affine_xQmP: ExtensionFieldElement{ A: Fp751Element([0x6ffb44306a153779, 0xc0ffef21f2f918f3, 0x196c46d35d77f778, 0x4a73f80452edcfe6, 0x9b00836bce61c67f, 0x387879418d84219e, 0x20700cf9fc1ec5d1, 0x1dfe2356ec64155e, 0xf8b9e33038256b1c, 0xd2aaf2e14bada0f0, 0xb33b226e79a4e313, 0x6be576fad4e5]), B: Fp751Element([0x7db5dbc88e00de34, 0x75cc8cb9f8b6e11e, 0x8c8001c04ebc52ac, 0x67ef6c981a0b5a94, 0xc3654fbe73230738, 0xc6a46ee82983ceca, 0xed1aa61a27ef49f0, 0x17fe5a13b0858fe0, 0x9ae0ca945a4c6b3c, 0x234104a218ad8878, 0xa619627166104394, 0x556a01ff2e7e]) }
    };

    const SHARED_SECRET_BOB_PUBLIC: SIDHPublicKeyBob = SIDHPublicKeyBob{
        affine_xP: ExtensionFieldElement{ A: Fp751Element([0x6e1b8b250595b5fb, 0x800787f5197d963b, 0x6f4a4e314162a8a4, 0xe75cba4d37c02128, 0x2212e7579817a216, 0xd8a5fdb0ab2f843c, 0x44230c9f998cfd6c, 0x311ff789b26aa292, 0x73d05c379ff53e40, 0xddd8f5a223bad56c, 0x94b611e6e931c8b5, 0x4d6b9bfe3555]), B: Fp751Element([0x1a3686cfc8381294, 0x57f089b14f639cc4, 0xdb6a1565f2f5cabe, 0x83d67e8f6a02f215, 0x1946272593815e87, 0x2d839631785ca74c, 0xf149dcb2dee2bee, 0x705acd79efe405bf, 0xae3769b67687fbed, 0xacd5e29f2c203cb0, 0xdd91f08fa3153e08, 0x5a9ad8cb7400]) },
        affine_xQ: ExtensionFieldElement{ A: Fp751Element([0xd30ed48b8c0d0c4a, 0x949cad95959ec462, 0x188675581e9d1f2a, 0xf57ed3233d33031c, 0x564c6532f7283ce7, 0x80cbef8ee3b66ecb, 0x5c687359315f22ce, 0x1da950f8671fac50, 0x6fa6c045f513ef6, 0x25ffc65a8da12d4a, 0x8b0f4ac0f5244f23, 0xadcb0e07fd92]), B: Fp751Element([0x37a43cd933ebfec4, 0x2a2806ef28dacf84, 0xd671fe718611b71e, 0xef7d73f01a676326, 0x99db1524e5799cf2, 0x860271dfbf67ff62, 0xedc2a0a14114bcf, 0x6c7b9b14b1264e5a, 0xf52de61707dc38b4, 0xccddb13fcc691f5a, 0x80f37a1220163920, 0x6a9175b9d5a1]) },
        affine_xQmP: ExtensionFieldElement{ A: Fp751Element([0xf08af9e695c626da, 0x7a4b4d52b54e1b38, 0x980272cd4c8b8c10, 0x1afcb6151d113176, 0xaef7dbd877c00f0c, 0xe8a5ea89078700c3, 0x520c1901aa8323fa, 0xfba049c947f3383a, 0x1c38abcab48be9af, 0x9f1212b923481ea, 0x1522da3457a7c293, 0xb746f78e3a61]), B: Fp751Element([0x48010d0b48491128, 0x6d1c5c509f99f450, 0xaa3522330e3a8a62, 0x872aaf46193b2bb2, 0xc89260a2d8508973, 0x98bbbebf5524be83, 0x35711d01d895c217, 0x5e44e09ec506ed7, 0xac653a760ef6fd58, 0x5837954e30ad688d, 0xcbd3e9a1b5661da8, 0x15547f5d091a]) }
    };

    #[bench]
    fn alice_keygen(b: &mut Bencher) {
        let mut rng = thread_rng();

        b.iter(|| generate_alice_keypair(&mut rng))
    }

    #[bench]
    fn alice_keygen_slow(b: &mut Bencher) {
        // m_A = 2*randint(0,2^371)
        let m_A: [u8; 48] = [248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0];
        let alice_secret_key = SIDHSecretKeyAlice{ scalar: m_A };

        b.iter(|| test::alice_keygen_slow(&alice_secret_key))
    }

    #[bench]
    fn bob_keygen(b: &mut Bencher) {
        let mut rng = thread_rng();

        b.iter(|| generate_bob_keypair(&mut rng))
    }

    #[bench]
    fn bob_keygen_slow(b: &mut Bencher) {
        // m_B = 3*randint(0,3^238)
        let m_B: [u8; 48] = [246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0];
        let bob_secret_key = SIDHSecretKeyBob{ scalar: m_B };

        b.iter(|| test::bob_keygen_slow(&bob_secret_key))
    }

    #[bench]
    fn shared_secret_alice(b: &mut Bencher) {
        // m_A = 2*randint(0,2^371)
        let m_A: [u8; 48] = [248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0];
        let alice_secret = SIDHSecretKeyAlice{ scalar: m_A };

        b.iter(|| alice_secret.shared_secret(&SHARED_SECRET_BOB_PUBLIC));
    }

    #[bench]
    fn shared_secret_alice_slow(b: &mut Bencher) {
        // m_A = 2*randint(0,2^371)
        let m_A: [u8; 48] = [248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0];
        let alice_secret = SIDHSecretKeyAlice{ scalar: m_A };

        b.iter(|| test::alice_shared_secret_slow(&SHARED_SECRET_BOB_PUBLIC, &alice_secret))
    }

    #[bench]
    fn shared_secret_bob(b: &mut Bencher) {
        // m_B = 3*randint(0,3^238)
        let m_B: [u8; 48] = [246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0];
        let bob_secret = SIDHSecretKeyBob{ scalar: m_B };

        b.iter(|| bob_secret.shared_secret(&SHARED_SECRET_ALICE_PUBLIC))
    }

    #[bench]
    fn shared_secret_bob_slow(b: &mut Bencher) {
        // m_B = 3*randint(0,3^238)
        let m_B: [u8; 48] = [246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0];
        let bob_secret = SIDHSecretKeyBob{ scalar: m_B };

        b.iter(|| test::bob_shared_secret_slow(&SHARED_SECRET_ALICE_PUBLIC, &bob_secret))
    }
}
