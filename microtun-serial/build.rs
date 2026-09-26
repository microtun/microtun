//! Compiles the tiny C shim against the *installed* libfuse3 headers and
//! links libfuse3.
//!
//! The shim is what keeps this crate robust across libfuse 3.x releases:
//! `struct fuse_file_info` is full of bitfields and has changed layout
//! between versions, so we never describe it in Rust. The C compiler reads
//! the real header and the shim hands Rust plain integers instead.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    println!("cargo:rerun-if-changed=csrc/shim.c");

    // Probe without emitting link flags yet: the static shim must come
    // *before* -lfuse3 on the linker command line.
    let fuse = pkg_config::Config::new()
        .atleast_version("3.0")
        .cargo_metadata(false)
        .probe("fuse3")
        .unwrap_or_else(|e| {
            panic!(
                "could not find libfuse3 via pkg-config ({e}).\n\
                 Install the development package, e.g.\n  \
                 Debian/Ubuntu: apt install libfuse3-dev pkg-config\n  \
                 Fedora:        dnf install fuse3-devel pkgconf\n  \
                 Arch:          pacman -S fuse3 pkgconf"
            )
        });

    let mut build = cc::Build::new();
    build
        .file("csrc/shim.c")
        .warnings(true)
        .extra_warnings(true);
    for path in &fuse.include_paths {
        build.include(path);
    }
    for (name, value) in &fuse.defines {
        build.define(name, value.as_deref());
    }
    build.compile("cuse_shim");

    for path in &fuse.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    for lib in &fuse.libs {
        println!("cargo:rustc-link-lib={lib}");
    }
}
