use std::{env, path::PathBuf};

fn main() {
    emit_linker_memory();
    microtun_firmware_build::emit_firmware_public_key();
    microtun_firmware_build::emit_firmware_version();
}

fn emit_linker_memory() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source = manifest.join("../memory.x");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::copy(&source, out.join("memory.x")).expect("copy memory.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={}", source.display());
}
