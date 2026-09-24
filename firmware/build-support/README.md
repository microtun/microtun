# microtun-firmware-build

Build-script support shared by the board firmware crates. Each board's `build.rs` calls
[`emit_firmware_public_key`] and [`emit_firmware_version`], which embed the firmware-update
verification key and the MCUboot anti-rollback version into `OUT_DIR`.

## Firmware update key

The key is read from the Ed25519 public-key PEM named by `MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH`.
CI release builds fetch it from the signing service.

When the variable is unset, the build falls back to the development key in
[`dev.pem`](dev.pem) and prints a Cargo warning. Its
private half was destroyed when it was generated, so **firmware built with the development key
boots normally but rejects every firmware update.** That makes a plain `cargo build` work for
anyone, and makes an accidental development build harmless rather than a signing hole.

To test over-the-air updates locally, create your own key pair and point the build at it:

```sh
imgtool keygen -k my-dev-signing.pem -t ed25519
imgtool getpub -k my-dev-signing.pem -e pem > my-dev-public.pem
export MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH="$PWD/my-dev-public.pem"
```

Release builds set `MICROTUN_FIRMWARE_REQUIRE_RELEASE_KEY=1`. With it set, a missing
`MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH`, or one that points at the development key, fails the
build.