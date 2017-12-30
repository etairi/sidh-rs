#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(unused_imports)]

#![feature(iterator_step_by)]
#![feature(test)]

//#![cfg_attr(not(feature = "std"), no_std)]
//#![cfg_attr(feature = "bench", feature(test))]

//#[cfg(feature = "std")]
extern crate core;

// Used for traits related to constant-time code.
extern crate subtle;

//#[cfg(all(test, feature = "bench"))]
extern crate test;
#[cfg(test)]
extern crate quickcheck;

extern crate rand;

mod constants;
mod field;
mod curve;
mod isogeny;
mod sidh;
