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
#![allow(unused_variables)]
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
//! TThe library provides a generic field arithmetic implementation, therefore, making it 
//! compatible with many different architectures (such as x64, x86, and ARM).

//-----------------------------------------------------------------------------//
//                          External Dependencies                              //
//-----------------------------------------------------------------------------//

#[cfg(feature = "std")]
extern crate core;

extern crate rand;
extern crate rand_core;
extern crate heapless;

#[cfg(all(test, feature = "bench"))]
extern crate test;
#[cfg(any(test, feature = "bench"))]
extern crate quickcheck;

// Used for traits related to constant-time code.
extern crate subtle;

//-----------------------------------------------------------------------------//
//                             Internal Modules                                //
//-----------------------------------------------------------------------------//

// Arithmetic backends (for x64 and x86 arhitectures) live here.
pub(crate) mod backend;
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
