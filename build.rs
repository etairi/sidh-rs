#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/field_amd64.S")
        .compile("field");
}
