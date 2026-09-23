use std::path::{Path, PathBuf};

use base64::Engine as _;

const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn main() {
    emit_linker_memory();
    emit_firmware_public_key();
    emit_firmware_version();
}

fn emit_linker_memory() {
    let manifest =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source = manifest.join("../memory.x");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::copy(&source, out.join("memory.x")).expect("copy memory.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={}", source.display());
}

fn emit_firmware_public_key() {
    cargo_emit::rerun_if_env_changed!("MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH");
    cargo_emit::rerun_if_env_changed!("MICROTUN_FIRMWARE_PUBLIC_KEY_CACHE_KEY");

    let path = std::env::var("MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH").expect(
        "MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH must point to an Ed25519 public-key PEM; release builds fetch it from the signing service",
    );
    let path = resolve_manifest_relative_path(path.trim());
    println!("cargo:rerun-if-changed={}", path.display());

    let raw = read_ed25519_public_key_pem(&path);
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out.join("firmware-public-key.bin"), raw).expect("write firmware public key");
}

fn emit_firmware_version() {
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Cargo's package version is the canonical firmware SemVer. MCUboot's
    // header stores major/minor/revision plus a numeric build field; releases
    // use the SemVer core with build=0. Pre-release/build metadata would have
    // ambiguous rollback ordering here, so reject it at build time.
    let raw = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let pre = std::env::var("CARGO_PKG_VERSION_PRE").unwrap_or_default();
    if !pre.is_empty() || raw.contains('+') {
        panic!(
            "firmware package version must be a release SemVer x.y.z without pre-release or build metadata: {raw}"
        );
    }

    let major: u8 = std::env::var("CARGO_PKG_VERSION_MAJOR")
        .expect("CARGO_PKG_VERSION_MAJOR")
        .parse()
        .expect("firmware SemVer major must fit MCUboot u8");
    let minor: u8 = std::env::var("CARGO_PKG_VERSION_MINOR")
        .expect("CARGO_PKG_VERSION_MINOR")
        .parse()
        .expect("firmware SemVer minor must fit MCUboot u8");
    let revision: u16 = std::env::var("CARGO_PKG_VERSION_PATCH")
        .expect("CARGO_PKG_VERSION_PATCH")
        .parse()
        .expect("firmware SemVer patch must fit MCUboot u16");

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(
        out.join("firmware-version.rs"),
        format!(
            "const FIRMWARE_MCUBOOT_VERSION: ImageVersion = ImageVersion {{ major: {major}, minor: {minor}, revision: {revision}, build: 0 }};\n"
        ),
    )
    .expect("write firmware version");
}

fn resolve_manifest_relative_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
            .join(path)
    }
}

fn read_ed25519_public_key_pem(path: &Path) -> [u8; 32] {
    let pem = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read firmware public key PEM {}: {error}", path.display()));

    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";

    let begin = pem.find(BEGIN).unwrap_or_else(|| {
        panic!(
            "firmware public key PEM {} must contain {BEGIN}",
            path.display()
        )
    });
    let body_start = begin + BEGIN.len();
    let end = pem[body_start..]
        .find(END)
        .map(|offset| body_start + offset)
        .unwrap_or_else(|| {
            panic!(
                "firmware public key PEM {} must contain {END}",
                path.display()
            )
        });

    let encoded: String = pem[body_start..end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap_or_else(|error| {
            panic!(
                "decode firmware public key PEM {} as base64: {error}",
                path.display()
            )
        });

    decode_spki_public_key(&der, &format!("firmware public key PEM {}", path.display()))
}

fn decode_spki_public_key(der: &[u8], source: &str) -> [u8; 32] {
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(ED25519_SPKI_PREFIX) {
        panic!(
            "{source} must contain an Ed25519 SubjectPublicKeyInfo public key (44-byte DER, as emitted by imgtool getpub --encoding pem/raw)"
        );
    }

    der[ED25519_SPKI_PREFIX.len()..]
        .try_into()
        .expect("32-byte Ed25519 public key")
}
