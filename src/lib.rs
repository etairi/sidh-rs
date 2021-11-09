// This file is part of sidh-rs.
// Copyright (c) 2017 Erkan Tairi
// See LICENSE for licensing information.
//
// Author:
// - Erkan Tairi <erkan.tairi@gmail.com>
//

extern crate subtle;
extern crate heapless;
extern crate rand;

#[cfg(test)]
extern crate quickcheck;

#[allow(non_snake_case)]
#[allow(unused_variables)]
#[allow(unused)]
pub(crate) mod field;
#[allow(non_snake_case)]
#[allow(unused)]
pub(crate) mod curve;
#[allow(non_snake_case)]
pub(crate) mod isogeny;
#[allow(non_snake_case)]
#[allow(unused)]
#[macro_use]
pub(crate) mod fp;

pub mod constants;
#[allow(unused_assignments)]
#[allow(non_snake_case)]
pub mod sidh;
