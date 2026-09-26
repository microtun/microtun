#![no_std]
#![forbid(unsafe_code)]

//! Streaming validation for the subset of the MCUboot image format used by
//! microtun firmware updates.
//!
//! This crate deliberately implements an image *envelope*, not a bootloader.
//! The firmware payload is streamed to a caller-provided sink while the MCUboot
//! header and TLVs are authenticated. This lets targets such as ESP32 keep their
//! native bootloader/OTA-slot machinery while sharing one signed distribution
//! format.
//!
//! Two properties are enforced here rather than left to callers:
//!
//! * **Anti-rollback.** The signed MCUboot image version must be greater than
//!   or equal to [`Policy::min_version`], which callers set from the running
//!   firmware's own SemVer. The version lives in the authenticated image header.
//! * **Read-back verification.** [`VerifiedImage`] retains the image header and
//!   the protected TLV block, which are the only parts of the container not
//!   written to the slot. [`verify_stored_image`] recomputes the canonical
//!   MCUboot digest — `header || payload-read-back-from-flash || protected
//!   TLVs` — and compares it against the digest that the signature already
//!   covered, the same thing MCUboot's own `bootutil_img_validate` does before
//!   a slot is booted. Without it the only thing ever verified is the in-flight
//!   copy, not what was actually stored.

use ed25519_dalek::{Signature, VerifyingKey};
use embedded_storage::nor_flash::ReadNorFlash;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const IMAGE_MAGIC: u32 = 0x96f3_b83d;
pub const IMAGE_HEADER_SIZE: usize = 32;
/// Upper bound on the protected TLV area this crate will accept.
///
/// The area has to be retained in RAM so the canonical digest can be recomputed
/// against flash. An imgtool VID + CID pair needs 44 bytes (4 info + two 20-byte
/// UUID TLVs); the limit leaves room for some additional protected metadata
/// without revisiting this.
pub const MAX_PROTECTED_TLV_SIZE: usize = 64;
/// Stack buffer used when reading a slot back for verification.
const READ_BACK_CHUNK: usize = 256;
pub const TLV_INFO_MAGIC: u16 = 0x6907;
pub const TLV_PROTECTED_INFO_MAGIC: u16 = 0x6908;

const TLV_KEYHASH: u16 = 0x01;
const TLV_SHA256: u16 = 0x10;
const TLV_ED25519: u16 = 0x24;
const TLV_SIG_PURE: u16 = 0x25;
const TLV_UUID_VID: u16 = 0x74;
const TLV_UUID_CID: u16 = 0x75;

// DER SubjectPublicKeyInfo prefix used by MCUboot imgtool's Ed25519
// `get_public_bytes()`, followed by the 32-byte raw public key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageVersion {
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub build: u32,
}

impl ImageVersion {
    /// Compare only the SemVer core (`major.minor.patch`). MCUboot's numeric
    /// build field is intentionally not part of rollback precedence because
    /// SemVer build metadata does not affect version ordering.
    fn semver_is_older_than(self, other: Self) -> bool {
        (self.major, self.minor, self.revision) < (other.major, other.minor, other.revision)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageHeader {
    pub load_address: u32,
    pub header_size: u16,
    pub protected_tlv_size: u16,
    pub image_size: u32,
    pub flags: u32,
    pub version: ImageVersion,
}

impl ImageHeader {
    pub fn parse(bytes: &[u8; IMAGE_HEADER_SIZE]) -> Result<Self, Error> {
        if le_u32(&bytes[0..4]) != IMAGE_MAGIC {
            return Err(Error::InvalidMagic);
        }

        let header = Self {
            load_address: le_u32(&bytes[4..8]),
            header_size: le_u16(&bytes[8..10]),
            protected_tlv_size: le_u16(&bytes[10..12]),
            image_size: le_u32(&bytes[12..16]),
            flags: le_u32(&bytes[16..20]),
            version: ImageVersion {
                major: bytes[20],
                minor: bytes[21],
                revision: le_u16(&bytes[22..24]),
                build: le_u32(&bytes[24..28]),
            },
        };

        if usize::from(header.header_size) != IMAGE_HEADER_SIZE {
            return Err(Error::UnsupportedHeaderSize);
        }
        if header.load_address != 0 {
            return Err(Error::UnsupportedLoadAddress);
        }
        if header.flags != 0 {
            return Err(Error::UnsupportedImageFlags);
        }
        if header.image_size == 0 {
            return Err(Error::EmptyImage);
        }
        if header.protected_tlv_size != 0 && header.protected_tlv_size < 4 {
            return Err(Error::InvalidProtectedTlvSize);
        }

        Ok(header)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageIdentity {
    pub vid: [u8; 16],
    pub cid: [u8; 16],
}

impl ImageIdentity {
    /// Derive the same UUIDs as MCUboot imgtool for named `--vid` / `--cid`
    /// values.
    ///
    /// imgtool computes `VID = UUIDv5(DNS, vid)` and then
    /// `CID = UUIDv5(VID, cid)`. Keeping the human-readable names in firmware
    /// avoids copying opaque UUID byte arrays while remaining byte-for-byte
    /// compatible with the protected UUID TLVs emitted by imgtool.
    pub fn from_imgtool_names(vid: &str, cid: &str) -> Self {
        let vid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, vid.as_bytes());
        let cid = Uuid::new_v5(&vid, cid.as_bytes());
        Self {
            vid: vid.into_bytes(),
            cid: cid.into_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Expected vendor UUID. `None` preserves compatibility with older callers
    /// that only pinned the component UUID. Named imgtool policies set this.
    pub expected_vid: Option<[u8; 16]>,
    pub expected_cid: [u8; 16],
    pub max_image_size: u32,
    /// Oldest signed image version this device will accept. Callers set this
    /// from the running firmware's own SemVer so that an attacker holding an
    /// older but validly signed release cannot downgrade the device onto it.
    /// Only `major.minor.revision` participate in precedence; `build` is ignored.
    pub min_version: ImageVersion,
}

impl Policy {
    /// Construct a policy from the same human-readable VID/CID names passed to
    /// `imgtool sign --vid <vid> --cid <cid>`.
    pub fn from_imgtool_names(
        vid: &str,
        cid: &str,
        max_image_size: u32,
        min_version: ImageVersion,
    ) -> Self {
        let identity = ImageIdentity::from_imgtool_names(vid, cid);
        Self {
            expected_vid: Some(identity.vid),
            expected_cid: identity.cid,
            max_image_size,
            min_version,
        }
    }

    /// Construct a policy from raw UUID bytes while validating both UUID TLVs.
    pub const fn from_raw_ids(
        expected_vid: [u8; 16],
        expected_cid: [u8; 16],
        max_image_size: u32,
        min_version: ImageVersion,
    ) -> Self {
        Self {
            expected_vid: Some(expected_vid),
            expected_cid,
            max_image_size,
            min_version,
        }
    }

    /// Legacy constructor for images/policies that only pin the CID TLV.
    pub const fn from_raw_cid(
        expected_cid: [u8; 16],
        max_image_size: u32,
        min_version: ImageVersion,
    ) -> Self {
        Self {
            expected_vid: None,
            expected_cid,
            max_image_size,
            min_version,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedImage {
    pub header: ImageHeader,
    /// Digest over header + payload + protected TLVs, as signed.
    pub digest: [u8; 32],
    pub vid: Option<[u8; 16]>,
    pub cid: [u8; 16],
    pub container_size: u32,
    /// Raw image header, retained so [`verify_stored_image`] can rebuild the
    /// canonical digest from a slot that only holds the native payload.
    header_bytes: [u8; IMAGE_HEADER_SIZE],
    protected_tlv: [u8; MAX_PROTECTED_TLV_SIZE],
    protected_tlv_size: u16,
}

impl VerifiedImage {
    /// The protected TLV block exactly as it appeared in the container.
    pub fn protected_tlv(&self) -> &[u8] {
        &self.protected_tlv[..usize::from(self.protected_tlv_size)]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    InvalidPublicKey,
    InvalidMagic,
    UnsupportedHeaderSize,
    UnsupportedLoadAddress,
    UnsupportedImageFlags,
    EmptyImage,
    ImageTooLarge,
    InvalidProtectedTlvSize,
    InvalidTlvInfoMagic,
    InvalidTlvAreaSize,
    TruncatedTlv,
    DuplicateTlv,
    InvalidTlvLength,
    MissingSha256,
    MissingKeyHash,
    MissingSignature,
    MissingVid,
    MissingCid,
    VersionTooLow,
    ProtectedTlvAreaTooLarge,
    UnsupportedReadGranularity,
    WrongVid,
    WrongCid,
    UnsupportedPureSignature,
    HashMismatch,
    KeyHashMismatch,
    SignatureInvalid,
    IncompleteImage,
    InvalidPadding,
    /// The bytes in the target slot do not reproduce the signed digest.
    StoredImageInvalid,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FeedError<E> {
    Image(Error),
    Sink(E),
}

pub trait PayloadSink {
    type Error;

    /// Store raw application bytes at an offset relative to the start of the
    /// target application's slot.
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoredImageError<E> {
    Image(Error),
    Read(E),
}

/// Re-read a freshly written slot and confirm it reproduces the signed digest.
///
/// Callers must run this before making the slot bootable. Streaming
/// verification only proves that the bytes *arriving over the wire* were
/// authentic; a partial or failed flash program can still leave something else
/// behind, and nothing downstream would notice.
///
/// `source` is read at offsets relative to the start of the target slot, which
/// holds the native payload alone. The header and protected TLVs are supplied
/// from `image`, so the digest computed here is the same one the signature
/// covered — no image-specific or non-standard hash is involved.
pub fn verify_stored_image<S: ReadNorFlash>(
    source: &mut S,
    image: &VerifiedImage,
) -> Result<(), StoredImageError<S::Error>> {
    let read_size = S::READ_SIZE.max(1);
    if read_size > READ_BACK_CHUNK {
        return Err(StoredImageError::Image(Error::UnsupportedReadGranularity));
    }
    // Largest chunk that is both a multiple of the read granularity and fits
    // the scratch buffer.
    let chunk = READ_BACK_CHUNK / read_size * read_size;

    let mut hasher = Sha256::new();
    hasher.update(image.header_bytes);

    let mut buffer = [0u8; READ_BACK_CHUNK];
    let mut offset = 0u32;
    while offset < image.header.image_size {
        let remaining = (image.header.image_size - offset) as usize;
        let take = remaining.min(chunk);
        // A short tail still has to be read at the device's granularity; only
        // the bytes belonging to the image are hashed.
        let read_len = take.div_ceil(read_size) * read_size;
        source
            .read(offset, &mut buffer[..read_len])
            .map_err(StoredImageError::Read)?;
        hasher.update(&buffer[..take]);
        offset += take as u32;
    }

    hasher.update(image.protected_tlv());

    let digest: [u8; 32] = hasher.finalize().into();
    if digest != image.digest {
        return Err(StoredImageError::Image(Error::StoredImageInvalid));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TlvAreaKind {
    Protected,
    Regular,
}

struct TlvArea {
    kind: TlvAreaKind,
    expected_magic: u16,
    expected_total: Option<usize>,
    total: Option<usize>,
    consumed: usize,
    info: [u8; 4],
    info_fill: usize,
    entry_header: [u8; 4],
    entry_header_fill: usize,
    entry_type: u16,
    entry_len: usize,
    entry_fill: usize,
    entry_value: [u8; 64],
    entry_collect: bool,
}

impl TlvArea {
    const fn new(kind: TlvAreaKind, expected_magic: u16, expected_total: Option<usize>) -> Self {
        Self {
            kind,
            expected_magic,
            expected_total,
            total: None,
            consumed: 0,
            info: [0; 4],
            info_fill: 0,
            entry_header: [0; 4],
            entry_header_fill: 0,
            entry_type: 0,
            entry_len: 0,
            entry_fill: 0,
            entry_value: [0; 64],
            entry_collect: false,
        }
    }

    fn is_complete(&self) -> bool {
        self.total == Some(self.consumed)
    }

    fn feed(&mut self, input: &[u8], found: &mut FoundTlvs) -> Result<usize, Error> {
        let mut input_offset = 0;

        while input_offset < input.len() && !self.is_complete() {
            if self.info_fill < 4 {
                let take = (4 - self.info_fill).min(input.len() - input_offset);
                self.info[self.info_fill..self.info_fill + take]
                    .copy_from_slice(&input[input_offset..input_offset + take]);
                self.info_fill += take;
                self.consumed += take;
                input_offset += take;

                if self.info_fill == 4 {
                    let magic = le_u16(&self.info[0..2]);
                    let total = usize::from(le_u16(&self.info[2..4]));
                    if magic != self.expected_magic {
                        return Err(Error::InvalidTlvInfoMagic);
                    }
                    if total < 4 {
                        return Err(Error::InvalidTlvAreaSize);
                    }
                    if let Some(expected) = self.expected_total {
                        if total != expected {
                            return Err(Error::InvalidTlvAreaSize);
                        }
                    }
                    self.total = Some(total);
                }
                continue;
            }

            let total = self.total.ok_or(Error::InvalidTlvAreaSize)?;
            if self.consumed == total {
                break;
            }

            if self.entry_header_fill < 4 {
                let remaining_area = total - self.consumed;
                if remaining_area < 4 - self.entry_header_fill {
                    return Err(Error::TruncatedTlv);
                }
                let take = (4 - self.entry_header_fill).min(input.len() - input_offset);
                self.entry_header[self.entry_header_fill..self.entry_header_fill + take]
                    .copy_from_slice(&input[input_offset..input_offset + take]);
                self.entry_header_fill += take;
                self.consumed += take;
                input_offset += take;

                if self.entry_header_fill == 4 {
                    self.entry_type = le_u16(&self.entry_header[0..2]);
                    self.entry_len = usize::from(le_u16(&self.entry_header[2..4]));
                    self.entry_fill = 0;
                    self.entry_collect = matches!(
                        self.entry_type,
                        TLV_KEYHASH
                            | TLV_SHA256
                            | TLV_ED25519
                            | TLV_SIG_PURE
                            | TLV_UUID_VID
                            | TLV_UUID_CID
                    );

                    if self.entry_len > total - self.consumed {
                        return Err(Error::TruncatedTlv);
                    }
                    if self.entry_collect && self.entry_len > self.entry_value.len() {
                        return Err(Error::InvalidTlvLength);
                    }
                    if self.entry_len == 0 {
                        self.finish_entry(found)?;
                    }
                }
                continue;
            }

            let remaining_entry = self.entry_len - self.entry_fill;
            let take = remaining_entry.min(input.len() - input_offset);
            if self.entry_collect {
                self.entry_value[self.entry_fill..self.entry_fill + take]
                    .copy_from_slice(&input[input_offset..input_offset + take]);
            }
            self.entry_fill += take;
            self.consumed += take;
            input_offset += take;

            if self.entry_fill == self.entry_len {
                self.finish_entry(found)?;
            }
        }

        Ok(input_offset)
    }

    fn finish_entry(&mut self, found: &mut FoundTlvs) -> Result<(), Error> {
        let value = &self.entry_value[..self.entry_len.min(self.entry_value.len())];
        let protected = matches!(self.kind, TlvAreaKind::Protected);

        match self.entry_type {
            TLV_KEYHASH if !protected => {
                set_once_array(&mut found.key_hash, value)?;
            }
            TLV_SHA256 if !protected => {
                set_once_array(&mut found.sha256, value)?;
            }
            TLV_ED25519 if !protected => {
                set_once_array(&mut found.signature, value)?;
            }
            TLV_SIG_PURE if !protected => {
                found.pure_signature = true;
            }
            TLV_UUID_VID if protected => {
                set_once_array(&mut found.vid, value)?;
            }
            TLV_UUID_CID if protected => {
                set_once_array(&mut found.cid, value)?;
            }
            _ => {}
        }

        self.entry_header_fill = 0;
        self.entry_type = 0;
        self.entry_len = 0;
        self.entry_fill = 0;
        self.entry_collect = false;
        self.entry_value.fill(0);
        Ok(())
    }
}

#[derive(Default)]
struct FoundTlvs {
    key_hash: Option<[u8; 32]>,
    sha256: Option<[u8; 32]>,
    signature: Option<[u8; 64]>,
    vid: Option<[u8; 16]>,
    cid: Option<[u8; 16]>,
    pure_signature: bool,
}

pub struct StreamingVerifier {
    public_key: VerifyingKey,
    expected_key_hash: [u8; 32],
    policy: Policy,
    header_bytes: [u8; IMAGE_HEADER_SIZE],
    header_fill: usize,
    header: Option<ImageHeader>,
    payload_offset: u32,
    protected: Option<TlvArea>,
    regular: TlvArea,
    found: FoundTlvs,
    hasher: Sha256,
    protected_bytes: [u8; MAX_PROTECTED_TLV_SIZE],
    protected_fill: usize,
    container_position: u32,
    complete: bool,
}

impl StreamingVerifier {
    pub fn new(public_key: [u8; 32], policy: Policy) -> Result<Self, Error> {
        let public_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| Error::InvalidPublicKey)?;

        let mut key_hasher = Sha256::new();
        key_hasher.update(ED25519_SPKI_PREFIX);
        key_hasher.update(public_key.as_bytes());
        let expected_key_hash: [u8; 32] = key_hasher.finalize().into();

        Ok(Self {
            public_key,
            expected_key_hash,
            policy,
            header_bytes: [0; IMAGE_HEADER_SIZE],
            header_fill: 0,
            header: None,
            payload_offset: 0,
            protected: None,
            regular: TlvArea::new(TlvAreaKind::Regular, TLV_INFO_MAGIC, None),
            found: FoundTlvs::default(),
            hasher: Sha256::new(),
            protected_bytes: [0; MAX_PROTECTED_TLV_SIZE],
            protected_fill: 0,
            container_position: 0,
            complete: false,
        })
    }

    pub fn header(&self) -> Option<ImageHeader> {
        self.header
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn container_size(&self) -> Option<u32> {
        self.complete.then_some(self.container_position)
    }

    pub fn feed<S: PayloadSink>(
        &mut self,
        mut input: &[u8],
        sink: &mut S,
    ) -> Result<(), FeedError<S::Error>> {
        while !input.is_empty() {
            if self.complete {
                if input.iter().any(|byte| *byte != 0x1a) {
                    return Err(FeedError::Image(Error::InvalidPadding));
                }
                return Ok(());
            }

            if self.header_fill < IMAGE_HEADER_SIZE {
                let take = (IMAGE_HEADER_SIZE - self.header_fill).min(input.len());
                self.header_bytes[self.header_fill..self.header_fill + take]
                    .copy_from_slice(&input[..take]);
                self.hasher.update(&input[..take]);
                self.header_fill += take;
                self.container_position = self.container_position.saturating_add(take as u32);
                input = &input[take..];

                if self.header_fill == IMAGE_HEADER_SIZE {
                    let header =
                        ImageHeader::parse(&self.header_bytes).map_err(FeedError::Image)?;
                    if header.image_size > self.policy.max_image_size {
                        return Err(FeedError::Image(Error::ImageTooLarge));
                    }
                    if usize::from(header.protected_tlv_size) > MAX_PROTECTED_TLV_SIZE {
                        return Err(FeedError::Image(Error::ProtectedTlvAreaTooLarge));
                    }
                    self.protected = (header.protected_tlv_size != 0).then(|| {
                        TlvArea::new(
                            TlvAreaKind::Protected,
                            TLV_PROTECTED_INFO_MAGIC,
                            Some(usize::from(header.protected_tlv_size)),
                        )
                    });
                    self.header = Some(header);
                }
                continue;
            }

            let header = self
                .header
                .ok_or(FeedError::Image(Error::IncompleteImage))?;
            if self.payload_offset < header.image_size {
                let remaining = (header.image_size - self.payload_offset) as usize;
                let take = remaining.min(input.len());
                let bytes = &input[..take];
                sink.write(self.payload_offset, bytes)
                    .map_err(FeedError::Sink)?;
                self.hasher.update(bytes);
                self.payload_offset += take as u32;
                self.container_position = self.container_position.saturating_add(take as u32);
                input = &input[take..];
                continue;
            }

            if let Some(protected) = self.protected.as_mut() {
                if !protected.is_complete() {
                    let remaining = usize::from(header.protected_tlv_size) - protected.consumed;
                    let take = remaining.min(input.len());
                    self.hasher.update(&input[..take]);
                    // Keep the protected block so the canonical digest can be
                    // rebuilt later against what is actually in flash.
                    self.protected_bytes[self.protected_fill..self.protected_fill + take]
                        .copy_from_slice(&input[..take]);
                    self.protected_fill += take;
                    let consumed = protected
                        .feed(&input[..take], &mut self.found)
                        .map_err(FeedError::Image)?;
                    debug_assert_eq!(consumed, take);
                    self.container_position = self.container_position.saturating_add(take as u32);
                    input = &input[take..];
                    continue;
                }
            }

            let consumed = self
                .regular
                .feed(input, &mut self.found)
                .map_err(FeedError::Image)?;
            if consumed == 0 {
                return Err(FeedError::Image(Error::InvalidTlvAreaSize));
            }
            self.container_position = self.container_position.saturating_add(consumed as u32);
            input = &input[consumed..];
            if self.regular.is_complete() {
                self.complete = true;
            }
        }

        Ok(())
    }

    pub fn finish(self) -> Result<VerifiedImage, Error> {
        if !self.complete {
            return Err(Error::IncompleteImage);
        }
        if self.found.pure_signature {
            return Err(Error::UnsupportedPureSignature);
        }

        let header = self.header.ok_or(Error::IncompleteImage)?;
        let expected_digest = self.found.sha256.ok_or(Error::MissingSha256)?;
        let key_hash = self.found.key_hash.ok_or(Error::MissingKeyHash)?;
        let signature_bytes = self.found.signature.ok_or(Error::MissingSignature)?;

        if key_hash != self.expected_key_hash {
            return Err(Error::KeyHashMismatch);
        }

        let digest: [u8; 32] = self.hasher.finalize().into();
        if digest != expected_digest {
            return Err(Error::HashMismatch);
        }

        let signature = Signature::from_bytes(&signature_bytes);
        self.public_key
            .verify_strict(&digest, &signature)
            .map_err(|_| Error::SignatureInvalid)?;

        // Everything below is a policy decision about an image that is now
        // known to be authentic. Checking it after the signature keeps the
        // decisions from being made on attacker-chosen values.
        if let Some(expected_vid) = self.policy.expected_vid {
            let vid = self.found.vid.ok_or(Error::MissingVid)?;
            if vid != expected_vid {
                return Err(Error::WrongVid);
            }
        }

        let cid = self.found.cid.ok_or(Error::MissingCid)?;
        if cid != self.policy.expected_cid {
            return Err(Error::WrongCid);
        }

        if header.version.semver_is_older_than(self.policy.min_version) {
            return Err(Error::VersionTooLow);
        }

        Ok(VerifiedImage {
            header,
            digest,
            vid: self.found.vid,
            cid,
            container_size: self.container_position,
            header_bytes: self.header_bytes,
            protected_tlv: self.protected_bytes,
            protected_tlv_size: header.protected_tlv_size,
        })
    }
}

fn set_once_array<const N: usize>(slot: &mut Option<[u8; N]>, value: &[u8]) -> Result<(), Error> {
    if value.len() != N {
        return Err(Error::InvalidTlvLength);
    }
    if slot.is_some() {
        return Err(Error::DuplicateTlv);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(value);
    *slot = Some(out);
    Ok(())
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use ed25519_dalek::{Signer as _, SigningKey};
    use embedded_storage::nor_flash::{ErrorType, NorFlashError, NorFlashErrorKind};

    use super::*;

    #[derive(Default)]
    struct VecSink(Vec<u8>);

    impl PayloadSink for VecSink {
        type Error = ();

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            assert_eq!(offset as usize, self.0.len());
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct SinkReadError;

    impl NorFlashError for SinkReadError {
        fn kind(&self) -> NorFlashErrorKind {
            NorFlashErrorKind::OutOfBounds
        }
    }

    impl ErrorType for VecSink {
        type Error = SinkReadError;
    }

    impl ReadNorFlash for VecSink {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let start = offset as usize;
            let end = start + bytes.len();
            if end > self.0.len() {
                return Err(SinkReadError);
            }
            bytes.copy_from_slice(&self.0[start..end]);
            Ok(())
        }

        fn capacity(&self) -> usize {
            self.0.len()
        }
    }

    fn policy(cid: [u8; 16]) -> Policy {
        Policy::from_raw_cid(
            cid,
            1024,
            ImageVersion {
                major: 0,
                minor: 0,
                revision: 0,
                build: 0,
            },
        )
    }

    fn push_tlv(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn build_image(payload: &[u8], cid: [u8; 16]) -> ([u8; 32], Vec<u8>) {
        build_image_with_version(
            payload,
            cid,
            ImageVersion {
                major: 1,
                minor: 2,
                revision: 3,
                build: 4,
            },
        )
    }

    fn build_image_with_version(
        payload: &[u8],
        cid: [u8; 16],
        version: ImageVersion,
    ) -> ([u8; 32], Vec<u8>) {
        build_image_with_ids(payload, None, cid, version)
    }

    fn build_image_with_ids(
        payload: &[u8],
        vid: Option<[u8; 16]>,
        cid: [u8; 16],
        version: ImageVersion,
    ) -> ([u8; 32], Vec<u8>) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing.verifying_key().to_bytes();

        let mut protected_body = Vec::new();
        if let Some(vid) = vid {
            push_tlv(&mut protected_body, TLV_UUID_VID, &vid);
        }
        push_tlv(&mut protected_body, TLV_UUID_CID, &cid);
        let protected_len = 4 + protected_body.len();

        let mut header = [0u8; IMAGE_HEADER_SIZE];
        header[0..4].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        header[8..10].copy_from_slice(&(IMAGE_HEADER_SIZE as u16).to_le_bytes());
        header[10..12].copy_from_slice(&(protected_len as u16).to_le_bytes());
        header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[20] = version.major;
        header[21] = version.minor;
        header[22..24].copy_from_slice(&version.revision.to_le_bytes());
        header[24..28].copy_from_slice(&version.build.to_le_bytes());

        let mut protected = Vec::new();
        protected.extend_from_slice(&TLV_PROTECTED_INFO_MAGIC.to_le_bytes());
        protected.extend_from_slice(&(protected_len as u16).to_le_bytes());
        protected.extend_from_slice(&protected_body);

        let mut hasher = Sha256::new();
        hasher.update(header);
        hasher.update(payload);
        hasher.update(&protected);
        let digest: [u8; 32] = hasher.finalize().into();

        let mut key_hasher = Sha256::new();
        key_hasher.update(ED25519_SPKI_PREFIX);
        key_hasher.update(public);
        let key_hash: [u8; 32] = key_hasher.finalize().into();
        let signature = signing.sign(&digest).to_bytes();

        let mut regular_body = Vec::new();
        push_tlv(&mut regular_body, TLV_SHA256, &digest);
        push_tlv(&mut regular_body, TLV_KEYHASH, &key_hash);
        push_tlv(&mut regular_body, TLV_ED25519, &signature);
        let regular_len = 4 + regular_body.len();

        let mut image = Vec::new();
        image.extend_from_slice(&header);
        image.extend_from_slice(payload);
        image.extend_from_slice(&protected);
        image.extend_from_slice(&TLV_INFO_MAGIC.to_le_bytes());
        image.extend_from_slice(&(regular_len as u16).to_le_bytes());
        image.extend_from_slice(&regular_body);
        (public, image)
    }

    #[test]
    fn derives_the_same_named_ids_as_imgtool() {
        let identity = ImageIdentity::from_imgtool_names("firmware.microtun.dev", "stm32h753zi");

        assert_eq!(
            identity.vid,
            [
                0xe0, 0x82, 0xa3, 0xae, 0x9a, 0x4a, 0x5f, 0xf8, 0xbd, 0xc1, 0x01, 0x45, 0x4e, 0xf6,
                0xda, 0xa0,
            ]
        );
        assert_eq!(
            identity.cid,
            [
                0xbc, 0xcb, 0x67, 0x62, 0x21, 0x80, 0x5f, 0xad, 0xa5, 0xea, 0x68, 0x14, 0xb9, 0x9e,
                0x4a, 0x72,
            ]
        );
    }

    #[test]
    fn named_policy_verifies_vid_and_cid_tlvs() {
        let identity = ImageIdentity::from_imgtool_names("firmware.microtun.dev", "stm32h753zi");
        let version = ImageVersion {
            major: 1,
            minor: 2,
            revision: 3,
            build: 4,
        };
        let (public, image) =
            build_image_with_ids(&[0xe9, 1, 2, 3], Some(identity.vid), identity.cid, version);
        let mut verifier = StreamingVerifier::new(
            public,
            Policy::from_imgtool_names(
                "firmware.microtun.dev",
                "stm32h753zi",
                1024,
                ImageVersion {
                    major: 0,
                    minor: 0,
                    revision: 0,
                    build: 0,
                },
            ),
        )
        .unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        let verified = verifier.finish().unwrap();

        assert_eq!(verified.vid, Some(identity.vid));
        assert_eq!(verified.cid, identity.cid);
    }

    #[test]
    fn named_policy_requires_vid_tlv() {
        let identity = ImageIdentity::from_imgtool_names("firmware.microtun.dev", "stm32h753zi");
        let (public, image) = build_image(&[0xe9, 1, 2, 3], identity.cid);
        let mut verifier = StreamingVerifier::new(
            public,
            Policy::from_imgtool_names(
                "firmware.microtun.dev",
                "stm32h753zi",
                1024,
                ImageVersion {
                    major: 0,
                    minor: 0,
                    revision: 0,
                    build: 0,
                },
            ),
        )
        .unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        assert_eq!(verifier.finish(), Err(Error::MissingVid));
    }

    #[test]
    fn named_policy_rejects_wrong_vid_even_when_cid_matches() {
        let identity = ImageIdentity::from_imgtool_names("firmware.microtun.dev", "stm32h753zi");
        let wrong_vid = ImageIdentity::from_imgtool_names("other.example", "stm32h753zi").vid;
        let version = ImageVersion {
            major: 1,
            minor: 2,
            revision: 3,
            build: 4,
        };
        let (public, image) =
            build_image_with_ids(&[0xe9, 1, 2, 3], Some(wrong_vid), identity.cid, version);
        let mut verifier = StreamingVerifier::new(
            public,
            Policy::from_imgtool_names(
                "firmware.microtun.dev",
                "stm32h753zi",
                1024,
                ImageVersion {
                    major: 0,
                    minor: 0,
                    revision: 0,
                    build: 0,
                },
            ),
        )
        .unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        assert_eq!(verifier.finish(), Err(Error::WrongVid));
    }

    #[test]
    fn streams_and_verifies_ed25519_mcuboot_image() {
        let cid = [0x42; 16];
        let payload = [0xe9, 1, 2, 3, 4, 5, 6, 7, 8];
        let (public, image) = build_image(&payload, cid);
        let mut verifier = StreamingVerifier::new(public, policy(cid)).unwrap();
        let mut sink = VecSink::default();

        for chunk in image.chunks(7) {
            verifier.feed(chunk, &mut sink).unwrap();
        }
        verifier.feed(&[0x1a; 11], &mut sink).unwrap();
        let verified = verifier.finish().unwrap();

        assert_eq!(sink.0, payload);
        verify_stored_image(&mut sink, &verified).unwrap();
        assert_eq!(verified.header.version.major, 1);
        assert_eq!(verified.header.version.minor, 2);
        assert_eq!(verified.header.version.revision, 3);
        assert_eq!(verified.header.version.build, 4);
        assert_eq!(verified.cid, cid);
    }

    #[test]
    fn rejects_wrong_component_id() {
        let cid = [0x42; 16];
        let (public, image) = build_image(&[0xe9, 1, 2, 3], cid);
        let mut verifier = StreamingVerifier::new(public, policy([0x99; 16])).unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        assert_eq!(verifier.finish(), Err(Error::WrongCid));
    }

    #[test]
    fn rejects_downgrade_below_the_running_version() {
        let cid = [0x42; 16];
        let candidate = ImageVersion {
            major: 1,
            minor: 4,
            revision: 9,
            build: 0,
        };
        let (public, image) = build_image_with_version(&[0xe9, 1, 2, 3], cid, candidate);
        let mut verifier = StreamingVerifier::new(
            public,
            Policy {
                min_version: ImageVersion {
                    major: 1,
                    minor: 5,
                    revision: 0,
                    build: 0,
                },
                ..policy(cid)
            },
        )
        .unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        assert_eq!(verifier.finish(), Err(Error::VersionTooLow));
    }

    #[test]
    fn accepts_equal_version() {
        let cid = [0x42; 16];
        let version = ImageVersion {
            major: 1,
            minor: 5,
            revision: 0,
            build: 0,
        };
        let (public, image) = build_image_with_version(&[0xe9, 1, 2, 3], cid, version);
        let mut verifier = StreamingVerifier::new(
            public,
            Policy {
                min_version: version,
                ..policy(cid)
            },
        )
        .unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        assert_eq!(verifier.finish().unwrap().header.version, version);
    }

    #[test]
    fn semver_build_field_does_not_affect_rollback_precedence() {
        let cid = [0x42; 16];
        let candidate = ImageVersion {
            major: 1,
            minor: 5,
            revision: 0,
            build: 1,
        };
        let (public, image) = build_image_with_version(&[0xe9, 1, 2, 3], cid, candidate);
        let mut verifier = StreamingVerifier::new(
            public,
            Policy {
                min_version: ImageVersion {
                    major: 1,
                    minor: 5,
                    revision: 0,
                    build: 999,
                },
                ..policy(cid)
            },
        )
        .unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        assert_eq!(verifier.finish().unwrap().header.version, candidate);
    }

    #[test]
    fn detects_a_corrupted_stored_image() {
        let cid = [0x42; 16];
        let payload = [0xe9, 1, 2, 3, 4, 5, 6, 7];
        let (public, image) = build_image(&payload, cid);
        let mut verifier = StreamingVerifier::new(public, policy(cid)).unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        let verified = verifier.finish().unwrap();

        // The stream authenticated, but the slot did not end up holding it.
        sink.0[3] ^= 0x01;
        assert_eq!(
            verify_stored_image(&mut sink, &verified),
            Err(StoredImageError::Image(Error::StoredImageInvalid))
        );
    }

    #[test]
    fn rejects_payload_tampering() {
        let cid = [0x42; 16];
        let (public, mut image) = build_image(&[0xe9, 1, 2, 3], cid);
        image[IMAGE_HEADER_SIZE + 1] ^= 0x80;
        let mut verifier = StreamingVerifier::new(public, policy(cid)).unwrap();
        let mut sink = VecSink::default();
        verifier.feed(&image, &mut sink).unwrap();
        assert_eq!(verifier.finish(), Err(Error::HashMismatch));
    }
}
