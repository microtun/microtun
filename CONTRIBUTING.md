# Contributing to microtun

Thanks for your interest in contributing to microtun.

## Contributor License Agreement

Before a contribution can be accepted, each contributor must complete the
applicable Contributor License Agreement (CLA). Pull requests may be reviewed
before the CLA is complete, but they cannot be merged until the contributor's
CLA status has been verified.

- Individual contributors: [`CLA-INDIVIDUAL.md`](CLA-INDIVIDUAL.md)
- Companies and other legal entities: [`CLA-ENTITY.md`](CLA-ENTITY.md)

The CLAs are adapted from the Project Harmony Version 1.0 contributor license
agreements using **Outbound License Option Five**. Attribution and a list of
adaptations appear in an appendix at the end of each CLA.

If you are contributing work owned by, or created on behalf of, an employer or
other organization, the Entity CLA or other appropriate authorization may also
be required.

### Signing the CLA

Until an automated CLA-signing service is configured, contact
`owner@microtun.dev` to execute the applicable CLA electronically. The signing
record should identify the contributor (or legal entity and authorized
representative), the applicable CLA, and the CLA version being accepted (for
example, "microtun ICLA Version 1.0 — 10 August 2026", as shown at the top of
each CLA).

Both CLAs are governed by German law (Section 6.1).

### Third-party material

Do not submit code, documentation, images, or other material whose copyright is
owned by someone else unless you have identified it clearly and have the right
to provide it for inclusion in microtun.

If a contribution contains third-party material, describe the material, its
source, its copyright holder, and the license or other permission that allows
it to be included in the pull request. Contact `owner@microtun.dev` before
submission if the permission or compatibility is unclear. The maintainers may
require the third-party material to be submitted separately by its owner or may
decline it.

## Building and testing

The repository has two Cargo workspaces: the host crates at the root, and the embedded
firmware in `firmware/`, which is excluded from the root workspace. CI checks both.

- **Formatting** uses unstable rustfmt options, so it needs a nightly rustfmt. Run
  `cargo +nightly fmt --all` at the root and again in `firmware/`. Stable rustfmt ignores the
  import-grouping rules, so it will not produce the layout CI expects.
- **Host crates:** `cargo clippy --workspace --all-targets` and `cargo test --workspace` at the
  root.
- **Firmware support code** builds for the host: in `firmware/`, run
  `cargo test -p microtun-firmware-build -p microtun-firmware-common`.
- **Firmware targets** build from the target directory, whose `.cargo/config.toml` selects the
  architecture, for example `cd firmware/stm32h753zi/app && cargo build`. No signing key or network
  access is needed: without `MICROTUN_FIRMWARE_PUBLIC_KEY_PEM_PATH`, the build embeds a
  development update key and prints a warning. Firmware built that way runs normally but rejects
  every firmware update. See [`firmware/build-support/README.md`](firmware/build-support/README.md)
  for using your own key to test updates.

## Pull requests

Please keep changes focused, include tests where practical, and update relevant
documentation when behavior or public interfaces change.

By submitting a pull request, you confirm that you have the right to submit the
contribution and that you will complete any CLA required for it to be accepted.