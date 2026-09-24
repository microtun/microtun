//! Build-script support shared by the board firmware crates.
//!
//! See the crate README for how the firmware-update key is selected.

use std::{
    env,
    path::{Path, PathBuf},
};

use base64::Engine as _;

/// Environment variable naming the Ed25519 public-key PEM to embed.
pub const PUBLIC_KEY_PATH_ENV: &str = "MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH";
/// Cache-busting companion to [`PUBLIC_KEY_PATH_ENV`], set by CI and the release Dockerfiles.
pub const PUBLIC_KEY_CACHE_KEY_ENV: &str = "MICROTUN_FIRMWARE_PUBLIC_KEY_CACHE_KEY";
/// When set to anything other than empty or `0`, the development key is refused.
pub const REQUIRE_RELEASE_KEY_ENV: &str = "MICROTUN_FIRMWARE_REQUIRE_RELEASE_KEY";

/// The development update key, whose private half does not exist.
pub const DEV_PUBLIC_KEY_PEM: &str = include_str!("../dev.pem");

const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Where the embedded firmware-update key came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// The PEM named by [`PUBLIC_KEY_PATH_ENV`].
    Configured(PathBuf),
    /// The built-in development key.
    Development,
}

/// A resolved firmware-update verification key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareKey {
    pub raw: [u8; 32],
    pub source: KeySource,
}

/// Raw bytes of the development key.
pub fn dev_public_key() -> [u8; 32] {
    parse_ed25519_public_key_pem(DEV_PUBLIC_KEY_PEM, "development firmware key")
        .expect("the bundled development key is a valid Ed25519 public key")
}

/// Select the firmware-update key from the build environment, without touching Cargo.
///
/// `configured` is the value of [`PUBLIC_KEY_PATH_ENV`]; relative paths are resolved against
/// `manifest_dir`, matching how Cargo runs build scripts.
pub fn resolve_public_key(
    configured: Option<&str>,
    require_release_key: bool,
    manifest_dir: &Path,
) -> Result<FirmwareKey, String> {
    let configured = configured.map(str::trim).filter(|path| !path.is_empty());
    let Some(path) = configured else {
        if require_release_key {
            return Err(format!(
                "{REQUIRE_RELEASE_KEY_ENV} is set, so {PUBLIC_KEY_PATH_ENV} must point to the \
                 release Ed25519 public-key PEM"
            ));
        }
        return Ok(FirmwareKey {
            raw: dev_public_key(),
            source: KeySource::Development,
        });
    };

    let path = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        manifest_dir.join(path)
    };
    let pem = std::fs::read_to_string(&path)
        .map_err(|error| format!("read firmware public key PEM {}: {error}", path.display()))?;
    let raw =
        parse_ed25519_public_key_pem(&pem, &format!("firmware public key PEM {}", path.display()))?;
    if require_release_key && raw == dev_public_key() {
        return Err(format!(
            "{} is the development firmware key, which cannot sign anything; \
             {REQUIRE_RELEASE_KEY_ENV} requires the release key",
            path.display()
        ));
    }
    Ok(FirmwareKey {
        raw,
        source: KeySource::Configured(path),
    })
}

/// Extract the 32-byte key from an Ed25519 SubjectPublicKeyInfo PEM.
pub fn parse_ed25519_public_key_pem(pem: &str, source: &str) -> Result<[u8; 32], String> {
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";

    let begin = pem
        .find(BEGIN)
        .ok_or_else(|| format!("{source} must contain {BEGIN}"))?;
    let body_start = begin + BEGIN.len();
    let end = pem[body_start..]
        .find(END)
        .map(|offset| body_start + offset)
        .ok_or_else(|| format!("{source} must contain {END}"))?;

    let encoded: String = pem[body_start..end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("decode {source} as base64: {error}"))?;
    decode_spki_public_key(&der, source)
}

/// Extract the 32-byte key from Ed25519 SubjectPublicKeyInfo DER.
pub fn decode_spki_public_key(der: &[u8], source: &str) -> Result<[u8; 32], String> {
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(ED25519_SPKI_PREFIX) {
        return Err(format!(
            "{source} must contain an Ed25519 SubjectPublicKeyInfo public key (44-byte DER, as \
             emitted by imgtool getpub --encoding pem/raw)"
        ));
    }
    Ok(der[ED25519_SPKI_PREFIX.len()..]
        .try_into()
        .expect("length checked above"))
}

/// MCUboot image version derived from the Cargo package version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McubootVersion {
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
}

/// Map a release SemVer onto MCUboot's `major.minor.revision+build` header fields.
///
/// Pre-release and build metadata would have ambiguous rollback ordering, so they are rejected.
pub fn mcuboot_version(
    version: &str,
    pre: &str,
    major: &str,
    minor: &str,
    patch: &str,
) -> Result<McubootVersion, String> {
    if !pre.is_empty() || version.contains('+') {
        return Err(format!(
            "firmware package version must be a release SemVer x.y.z without pre-release or \
             build metadata: {version}"
        ));
    }
    Ok(McubootVersion {
        major: major
            .parse()
            .map_err(|_| format!("firmware SemVer major must fit MCUboot u8: {major}"))?,
        minor: minor
            .parse()
            .map_err(|_| format!("firmware SemVer minor must fit MCUboot u8: {minor}"))?,
        revision: patch
            .parse()
            .map_err(|_| format!("firmware SemVer patch must fit MCUboot u16: {patch}"))?,
    })
}

/// Write `OUT_DIR/firmware-public-key.bin` for `include_bytes!` in the firmware.
pub fn emit_firmware_public_key() {
    println!("cargo:rerun-if-env-changed={PUBLIC_KEY_PATH_ENV}");
    println!("cargo:rerun-if-env-changed={PUBLIC_KEY_CACHE_KEY_ENV}");
    println!("cargo:rerun-if-env-changed={REQUIRE_RELEASE_KEY_ENV}");

    let configured = env::var(PUBLIC_KEY_PATH_ENV).ok();
    let require_release_key =
        env::var(REQUIRE_RELEASE_KEY_ENV).is_ok_and(|value| !value.is_empty() && value != "0");
    let key = resolve_public_key(
        configured.as_deref(),
        require_release_key,
        &env_path("CARGO_MANIFEST_DIR"),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    match &key.source {
        KeySource::Configured(path) => {
            println!("cargo:rerun-if-changed={}", path.display());
        }
        KeySource::Development => {
            println!(
                "cargo:warning=embedding the development firmware-update key: this build \
                 boots, but rejects every firmware update. Set {PUBLIC_KEY_PATH_ENV} to use a \
                 real key."
            );
        }
    }

    let out = env_path("OUT_DIR");
    std::fs::write(out.join("firmware-public-key.bin"), key.raw)
        .expect("write firmware public key");
}

/// Write `OUT_DIR/firmware-version.rs`, defining `FIRMWARE_MCUBOOT_VERSION: ImageVersion`.
pub fn emit_firmware_version() {
    println!("cargo:rerun-if-changed=Cargo.toml");

    let var = |name: &str| env::var(name).unwrap_or_default();
    let version = mcuboot_version(
        &var("CARGO_PKG_VERSION"),
        &var("CARGO_PKG_VERSION_PRE"),
        &var("CARGO_PKG_VERSION_MAJOR"),
        &var("CARGO_PKG_VERSION_MINOR"),
        &var("CARGO_PKG_VERSION_PATCH"),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let McubootVersion {
        major,
        minor,
        revision,
    } = version;
    std::fs::write(
        env_path("OUT_DIR").join("firmware-version.rs"),
        format!(
            "const FIRMWARE_MCUBOOT_VERSION: ImageVersion = ImageVersion {{ major: {major}, \
             minor: {minor}, revision: {revision}, build: 0 }};\n"
        ),
    )
    .expect("write firmware version");
}

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTHER_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEAuUU721jnlhW9XfsPpkFbdY9JOAkkqo9Govz2w09vO0Y=\n\
        -----END PUBLIC KEY-----\n";

    fn temp_pem(name: &str, contents: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("microtun-firmware-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn development_key_is_valid_and_distinct() {
        let dev = dev_public_key();
        assert_ne!(dev, [0; 32]);
        let other = parse_ed25519_public_key_pem(OTHER_KEY_PEM, "other").unwrap();
        assert_ne!(dev, other);
    }

    #[test]
    fn falls_back_to_development_key_when_unset_or_blank() {
        for configured in [None, Some(""), Some("  \n")] {
            let key = resolve_public_key(configured, false, Path::new("/")).unwrap();
            assert_eq!(key.source, KeySource::Development);
            assert_eq!(key.raw, dev_public_key());
        }
    }

    #[test]
    fn release_mode_requires_a_configured_key() {
        let error = resolve_public_key(None, true, Path::new("/")).unwrap_err();
        assert!(error.contains(PUBLIC_KEY_PATH_ENV), "{error}");
    }

    #[test]
    fn release_mode_refuses_the_development_key_by_value() {
        let path = temp_pem("dev-copy.pem", DEV_PUBLIC_KEY_PEM);
        let error = resolve_public_key(path.to_str(), true, Path::new("/")).unwrap_err();
        assert!(error.contains("development firmware key"), "{error}");
        // Outside release mode the same file is accepted, e.g. for local experiments.
        let key = resolve_public_key(path.to_str(), false, Path::new("/")).unwrap();
        assert_eq!(key.raw, dev_public_key());
    }

    #[test]
    fn configured_key_is_used_and_relative_paths_follow_the_manifest() {
        let path = temp_pem("release.pem", OTHER_KEY_PEM);
        let key = resolve_public_key(
            Some(path.file_name().unwrap().to_str().unwrap()),
            true,
            path.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(key.source, KeySource::Configured(path.clone()));
        assert_eq!(
            key.raw,
            parse_ed25519_public_key_pem(OTHER_KEY_PEM, "other").unwrap()
        );
    }

    #[test]
    fn missing_configured_file_is_an_error_not_a_fallback() {
        let error =
            resolve_public_key(Some("/nonexistent/key.pem"), false, Path::new("/")).unwrap_err();
        assert!(error.contains("/nonexistent/key.pem"), "{error}");
    }

    #[test]
    fn rejects_non_ed25519_or_malformed_pem() {
        assert!(parse_ed25519_public_key_pem("no markers", "x").is_err());
        let bad_base64 = "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----\n";
        assert!(parse_ed25519_public_key_pem(bad_base64, "x").is_err());
        // A P-256 SPKI (91 bytes) has the wrong length and algorithm prefix.
        let p256 = "-----BEGIN PUBLIC KEY-----\n\
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwREKKE/kbxQIFm35PMC3fb4rC49M\n\
            DcBfSBRXbbpkPTRrvYKkv+7X2zNr54NufsNsw5llQToUg1wUaQKhQMc7TA==\n\
            -----END PUBLIC KEY-----\n";
        assert!(parse_ed25519_public_key_pem(p256, "x").is_err());
    }

    #[test]
    fn maps_release_semver_to_mcuboot_fields() {
        assert_eq!(
            mcuboot_version("1.2.300", "", "1", "2", "300"),
            Ok(McubootVersion {
                major: 1,
                minor: 2,
                revision: 300
            })
        );
        assert!(mcuboot_version("1.2.3-rc.1", "rc.1", "1", "2", "3").is_err());
        assert!(mcuboot_version("1.2.3+build", "", "1", "2", "3").is_err());
        assert!(mcuboot_version("256.0.0", "", "256", "0", "0").is_err());
        assert!(mcuboot_version("0.0.70000", "", "0", "0", "70000").is_err());
    }
}
