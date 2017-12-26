extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/amd64/fp_x64.S")
        .compile("field");
}
