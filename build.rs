extern crate cc;

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    if target.contains("msvc") && host.contains("windows") {
        cc::Build::new()
            .file("src/amd64/fp_x64.asm")
            .file("src/amd64/util_x64.asm")
            .compile("sidh_helpers");
    } else {
        cc::Build::new()
            .file("src/amd64/fp_x64.S")
            .file("src/amd64/util_x64.S")
            .compile("sidh_helpers");
    }
}
