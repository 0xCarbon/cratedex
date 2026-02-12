fn main() {
    // Expose the compile-time target triple so service.rs can use it
    // to construct architecture-correct rustup toolchain paths.
    println!(
        "cargo::rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
