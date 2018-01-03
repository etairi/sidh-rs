// This file is part of sidh-rs.
// Copyright (c) 2017 Erkan Tairi
// See LICENSE for licensing information.
//
// Author:
// - Erkan Tairi <erkan.tairi@gmail.com>
//
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "nightly", feature(iterator_step_by))]
#![cfg_attr(feature = "bench", feature(test))]

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
//#![deny(missing_docs)] // Refuse to compile if documentation is missing.

//! # sidh
//! 
//! **An efficient supersingular isogeny-based cryptography library written in Rust.**
//! 
//! The library includes the ephemeral Diffie-Hellman key exchange (SIDH). This package 
//! does **not** implement SIDH  key validation, so it should only be used for ephemeral 
//! Diffie-Hellman, i.e. each keypair should be used at most once. This scheme is conjectured
//! to be secure against quantum computer attacks.
//! 
//! This library follows the usual naming convention, writing "Alice" for the party using
//! `2^e`-isogenies and "Bob" for the party using `3^e`-isogenies.
//! 
//! The implementation is intended for use on the `amd64` architecture only -- no generic 
//! field arithmetic implementation is provided.

//-----------------------------------------------------------------------------//
//                          External Dependencies                              //
//-----------------------------------------------------------------------------//

#[cfg(feature = "std")]
extern crate core;

#[cfg(feature = "std")]
extern crate rand;

#[cfg(all(test, feature = "bench"))]
extern crate test;
#[cfg(any(test, feature = "bench"))]
extern crate quickcheck;

// Used for traits related to constant-time code.
extern crate subtle;

//-----------------------------------------------------------------------------//
//                             Internal Modules                                //
//-----------------------------------------------------------------------------//

// Finite field arithmetic.
pub(crate) mod field;
// Internal curve operations which are not part of the public API.
#[macro_use]
pub(crate) mod curve;
// Internal isogeny operations which are not part of the public API.
pub(crate) mod isogeny;

//-----------------------------------------------------------------------------//
//                              Public Modules                                 //
//-----------------------------------------------------------------------------//

// Useful constants.
pub mod constants;
// Supersingular Isogeny Diffie-Hellman (SIDH) operations.
pub mod sidh;
