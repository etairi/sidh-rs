// This file is part of sidh-rs.
// Copyright (c) 2017 Erkan Tairi
// See LICENSE for licensing information.
//
// Author:
// - Erkan Tairi <erkan.tairi@gmail.com>
//

#[cfg(target_arch = "x86_64")]
pub mod x64;

#[cfg(target_arch = "x86")]
pub mod x86;