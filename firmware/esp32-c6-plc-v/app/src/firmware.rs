//! ESP32-C6 OTA slot handling.
//!
//! The TELNET/YMODEM/MCUboot transport lives in
//! `microtun_firmware_common::firmware`; what remains here is everything that
//! is specific to the ESP-IDF A/B layout: the flash sink over the inactive OTA
//! partition, the ESP application descriptor, and the otadata bookkeeping the
//! rollback-capable bootloader reads.

use embedded_io_async::{Read, Write};
use embedded_storage::{ReadStorage, Storage, nor_flash::NorFlash as _};
use esp_bootloader_esp_idf::{
    ota::OtaImageState,
    ota_updater::OtaUpdater,
    partitions::{
        AppPartitionSubType, DataPartitionSubType, Error as PartitionError, FlashRegion,
        PARTITION_TABLE_MAX_LEN, PartitionType, read_partition_table,
    },
};
use esp_storage::FlashStorage;
use log::{info, warn};
pub(crate) use microtun_firmware_common::firmware::FirmwareStatus;
use microtun_firmware_common::firmware::{ImageTransferError, TransferError, receive_signed_image};
use microtun_mcuboot::{
    ImageVersion, PayloadSink, Policy as McubootPolicy, StoredImageError, StreamingVerifier,
    verify_stored_image,
};

use crate::pet_watchdog;

const FIRMWARE_VENDOR_ID: &str = "firmware.microtun.dev";
const FIRMWARE_COMPONENT_ID: &str = "esp32-c6-plc-v";
const FIRMWARE_PUBLIC_KEY: &[u8; 32] =
    include_bytes!(concat!(env!("OUT_DIR"), "/firmware-public-key.bin"));

// Anti-rollback floor, emitted by build.rs from this app's Cargo package
// SemVer. Sign update envelopes with the same version via `imgtool sign -v
// <x.y.z>`; an older signed MCUboot header version is refused.
include!(concat!(env!("OUT_DIR"), "/firmware-version.rs"));

const ESP_IMAGE_MAGIC: u8 = 0xe9;
const ESP_IMAGE_HEADER_SIZE: usize = 24;
const ESP_IMAGE_SEGMENT_HEADER_SIZE: usize = 8;
const ESP_APP_DESC_OFFSET: usize = ESP_IMAGE_HEADER_SIZE + ESP_IMAGE_SEGMENT_HEADER_SIZE;
const ESP_APP_DESC_SIZE: usize = core::mem::size_of::<esp_bootloader_esp_idf::EspAppDesc>();
const ESP_APP_DESC_MAGIC: u32 = 0xabcd_5432;

// Raw otadata layout, mirroring `esp_bootloader_esp_idf::ota`. Two 32-byte
// select entries, one per otadata slot; the bootloader picks the entry with the
// highest sequence number.
const OTA_SELECT_ENTRY_SIZE: usize = 0x20;
const OTA_SELECT_SLOT0_OFFSET: u32 = 0x0000;
const OTA_SELECT_SLOT1_OFFSET: u32 = 0x1000;
const OTA_SELECT_STATE_OFFSET: usize = 24;
const OTA_SEQ_UNINITIALIZED: u32 = 0xffff_ffff;

pub(crate) fn ota_slot_name(slot: AppPartitionSubType) -> &'static str {
    match slot {
        AppPartitionSubType::Factory => "factory",
        AppPartitionSubType::Ota0 => "ota_0",
        AppPartitionSubType::Ota1 => "ota_1",
        _ => "other",
    }
}

fn ota_state_name(state: OtaImageState) -> &'static str {
    match state {
        OtaImageState::New => "new",
        OtaImageState::PendingVerify => "pending-verify",
        OtaImageState::Valid => "valid",
        OtaImageState::Invalid => "invalid",
        OtaImageState::Aborted => "aborted",
        OtaImageState::Undefined => "undefined",
    }
}

pub(crate) fn prepare_firmware_ota(flash: &mut FlashStorage<'static>) -> FirmwareStatus {
    match prepare_firmware_ota_inner(flash) {
        Ok(status) => status,
        Err(error) => {
            warn!("OTA metadata unavailable: {:?}", error);
            FirmwareStatus {
                slot: "unavailable",
                state: "unavailable",
                trial: false,
            }
        }
    }
}

fn prepare_firmware_ota_inner(
    flash: &mut FlashStorage<'static>,
) -> Result<FirmwareStatus, PartitionError> {
    let mut partition_buffer = [0u8; PARTITION_TABLE_MAX_LEN];
    let booted_slot = {
        let table = read_partition_table(flash, &mut partition_buffer)?;
        table
            .booted_partition()?
            .and_then(|partition| match partition.partition_type() {
                PartitionType::App(
                    slot @ (AppPartitionSubType::Ota0 | AppPartitionSubType::Ota1),
                ) => Some(slot),
                _ => None,
            })
    };

    let mut updater = OtaUpdater::new(flash, &mut partition_buffer)?;
    let mut selected = updater.selected_partition()?;

    // A freshly serial-flashed A/B layout has erased otadata. Espressif boots
    // ota_0 in that state, while the metadata API reports `Factory`. Seed the
    // OTA selector with the partition the MMU says is actually running before
    // asking OtaUpdater for an inactive slot.
    if selected == AppPartitionSubType::Factory
        && let Some(booted) = booted_slot
    {
        updater.ota_data()?.set_current_app_partition(booted)?;
        updater.set_current_ota_state(OtaImageState::Valid)?;
        selected = booted;
    }

    let state = updater
        .current_ota_state()
        .unwrap_or(OtaImageState::Undefined);

    // Do not confirm a newly selected image here. With an ESP-IDF rollback
    // bootloader, NEW becomes PENDING_VERIFY before the application starts and
    // any reset while it remains pending automatically selects the previous
    // valid slot. main.rs confirms only after the operational tunnel stack has
    // survived its trial-health window.
    Ok(FirmwareStatus {
        slot: ota_slot_name(selected),
        state: ota_state_name(state),
        trial: matches!(state, OtaImageState::New | OtaImageState::PendingVerify),
    })
}

pub(crate) fn confirm_firmware_ota(
    flash: &mut FlashStorage<'static>,
) -> Result<FirmwareStatus, PartitionError> {
    let mut partition_buffer = [0u8; PARTITION_TABLE_MAX_LEN];
    let mut updater = OtaUpdater::new(flash, &mut partition_buffer)?;
    let selected = updater.selected_partition()?;
    let state = updater
        .current_ota_state()
        .unwrap_or(OtaImageState::Undefined);

    if matches!(state, OtaImageState::New | OtaImageState::PendingVerify) {
        updater.set_current_ota_state(OtaImageState::Valid)?;
        info!(
            "OTA trial image {} passed health checks; marked valid",
            ota_slot_name(selected)
        );
        Ok(FirmwareStatus {
            slot: ota_slot_name(selected),
            state: ota_state_name(OtaImageState::Valid),
            trial: false,
        })
    } else {
        Ok(FirmwareStatus {
            slot: ota_slot_name(selected),
            state: ota_state_name(state),
            trial: false,
        })
    }
}

/// Write the image state into the otadata entry that
/// [`OtaUpdater::activate_next_partition`] is about to claim, *before* it is
/// claimed.
///
/// `set_current_app_partition` performs a read-modify-write of that entry: it
/// preserves whatever state field is already stored there and only bumps the
/// sequence number. Activating first and setting the state afterwards therefore
/// leaves a window in which a reset selects the new slot carrying a stale state
/// — quite possibly `Valid`, left over from that slot's previous life, which
/// skips the trial entirely and disables rollback. Priming the entry first
/// closes the window: the single write that makes the slot current already
/// carries `New`.
fn prime_next_ota_state(
    flash: &mut FlashStorage<'static>,
    state: OtaImageState,
) -> Result<(), PartitionError> {
    let mut partition_buffer = [0u8; PARTITION_TABLE_MAX_LEN];
    let table = read_partition_table(flash, &mut partition_buffer)?;
    let ota_data = table
        .find_partition(PartitionType::Data(DataPartitionSubType::Ota))?
        .ok_or(PartitionError::Invalid)?;
    let mut region = ota_data.as_embedded_storage(flash);

    let mut slot0 = [0u8; OTA_SELECT_ENTRY_SIZE];
    let mut slot1 = [0u8; OTA_SELECT_ENTRY_SIZE];
    ReadStorage::read(&mut region, OTA_SELECT_SLOT0_OFFSET, &mut slot0)?;
    ReadStorage::read(&mut region, OTA_SELECT_SLOT1_OFFSET, &mut slot1)?;
    let seq0 = u32::from_le_bytes([slot0[0], slot0[1], slot0[2], slot0[3]]);
    let seq1 = u32::from_le_bytes([slot1[0], slot1[1], slot1[2], slot1[3]]);

    // Mirror the crate's slot selection: the entry written next is the one that
    // is not currently authoritative.
    let current_is_slot0 = (seq0 == OTA_SEQ_UNINITIALIZED && seq1 == OTA_SEQ_UNINITIALIZED)
        || (seq0 != OTA_SEQ_UNINITIALIZED && (seq1 == OTA_SEQ_UNINITIALIZED || seq0 > seq1));
    let (offset, mut entry) = if current_is_slot0 {
        (OTA_SELECT_SLOT1_OFFSET, slot1)
    } else {
        (OTA_SELECT_SLOT0_OFFSET, slot0)
    };

    entry[OTA_SELECT_STATE_OFFSET..OTA_SELECT_STATE_OFFSET + 4]
        .copy_from_slice(&(state as u32).to_le_bytes());
    // The sequence number is left untouched, so this write cannot change which
    // partition the bootloader selects. `New` is 0, so the state field only
    // ever has bits cleared here: the write is safe on NOR flash whatever the
    // stale value was, and whatever erase semantics the storage layer uses.
    Storage::write(&mut region, offset, &entry)
}

#[derive(Debug)]
pub(crate) enum OtaSinkError {
    Flash(PartitionError),
    InvalidEspImage,
    InvalidEspAppDesc,
    NonSequentialWrite,
    OutOfBounds,
}

#[derive(Clone, Copy)]
pub(crate) struct EspAppMetadata {
    secure_version: u32,
    version: [u8; 32],
    project_name: [u8; 32],
    build_time: [u8; 16],
    build_date: [u8; 16],
    idf_ver: [u8; 32],
}

impl EspAppMetadata {
    fn parse(bytes: &[u8; ESP_APP_DESC_SIZE]) -> Result<Self, OtaSinkError> {
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != ESP_APP_DESC_MAGIC {
            return Err(OtaSinkError::InvalidEspAppDesc);
        }

        let metadata = Self {
            secure_version: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            version: bytes[16..48]
                .try_into()
                .map_err(|_| OtaSinkError::InvalidEspAppDesc)?,
            project_name: bytes[48..80]
                .try_into()
                .map_err(|_| OtaSinkError::InvalidEspAppDesc)?,
            build_time: bytes[80..96]
                .try_into()
                .map_err(|_| OtaSinkError::InvalidEspAppDesc)?,
            build_date: bytes[96..112]
                .try_into()
                .map_err(|_| OtaSinkError::InvalidEspAppDesc)?,
            idf_ver: bytes[112..144]
                .try_into()
                .map_err(|_| OtaSinkError::InvalidEspAppDesc)?,
        };

        metadata.version()?;
        metadata.project_name()?;
        metadata.build_time()?;
        metadata.build_date()?;
        metadata.idf_ver()?;
        Ok(metadata)
    }

    pub(crate) const fn secure_version(&self) -> u32 {
        self.secure_version
    }

    pub(crate) fn version(&self) -> Result<&str, OtaSinkError> {
        esp_app_desc_string(&self.version)
    }

    pub(crate) fn project_name(&self) -> Result<&str, OtaSinkError> {
        esp_app_desc_string(&self.project_name)
    }

    fn build_time(&self) -> Result<&str, OtaSinkError> {
        esp_app_desc_string(&self.build_time)
    }

    fn build_date(&self) -> Result<&str, OtaSinkError> {
        esp_app_desc_string(&self.build_date)
    }

    fn idf_ver(&self) -> Result<&str, OtaSinkError> {
        esp_app_desc_string(&self.idf_ver)
    }
}

fn esp_app_desc_string(bytes: &[u8]) -> Result<&str, OtaSinkError> {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..len]).map_err(|_| OtaSinkError::InvalidEspAppDesc)
}

struct EspOtaSink<'a> {
    region: FlashRegion<'a, FlashStorage<'static>>,
    erased_until: u32,
    written_until: u32,
    capacity: u32,
    saw_image_magic: bool,
    app_desc: [u8; ESP_APP_DESC_SIZE],
    app_desc_filled: usize,
}

impl<'a> EspOtaSink<'a> {
    fn new(region: FlashRegion<'a, FlashStorage<'static>>) -> Self {
        let capacity = region.partition_size() as u32;
        Self {
            region,
            erased_until: 0,
            written_until: 0,
            capacity,
            saw_image_magic: false,
            app_desc: [0; ESP_APP_DESC_SIZE],
            app_desc_filled: 0,
        }
    }

    /// The partition this sink writes to, for reading the image back.
    ///
    /// `FlashRegion` already reads at partition-relative offsets and its error
    /// type implements `NorFlashError`, so it is handed to
    /// `verify_stored_image` directly.
    fn region_mut(&mut self) -> &mut FlashRegion<'a, FlashStorage<'static>> {
        &mut self.region
    }

    fn app_metadata(&self) -> Result<EspAppMetadata, OtaSinkError> {
        if !self.saw_image_magic || self.app_desc_filled != ESP_APP_DESC_SIZE {
            return Err(OtaSinkError::InvalidEspAppDesc);
        }
        EspAppMetadata::parse(&self.app_desc)
    }
}

impl PayloadSink for EspOtaSink<'_> {
    type Error = OtaSinkError;

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        // Erase-ahead only works for a strictly forward stream: a backwards
        // write would land in a sector that has already been programmed, or
        // re-erase one that has. The verifier feeds sequentially, so make that
        // an enforced precondition rather than an assumption.
        if offset != self.written_until {
            return Err(OtaSinkError::NonSequentialWrite);
        }
        let end = offset
            .checked_add(bytes.len() as u32)
            .ok_or(OtaSinkError::OutOfBounds)?;
        if end > self.capacity {
            return Err(OtaSinkError::OutOfBounds);
        }
        if offset == 0 && !self.saw_image_magic {
            if bytes[0] != ESP_IMAGE_MAGIC {
                return Err(OtaSinkError::InvalidEspImage);
            }
            self.saw_image_magic = true;
        }

        // The ESP-IDF application descriptor is the first data in the first
        // image segment: 24-byte image header + 8-byte segment header. Capture
        // it while streaming so firmware identity comes from the actual ESP
        // application image, not the outer MCUboot envelope.
        let write_start = offset as usize;
        let write_end = end as usize;
        let app_desc_end = ESP_APP_DESC_OFFSET + ESP_APP_DESC_SIZE;
        let copy_start = write_start.max(ESP_APP_DESC_OFFSET);
        let copy_end = write_end.min(app_desc_end);
        if copy_start < copy_end {
            let source_start = copy_start - write_start;
            let destination_start = copy_start - ESP_APP_DESC_OFFSET;
            if destination_start != self.app_desc_filled {
                return Err(OtaSinkError::InvalidEspAppDesc);
            }
            let len = copy_end - copy_start;
            self.app_desc[destination_start..destination_start + len]
                .copy_from_slice(&bytes[source_start..source_start + len]);
            self.app_desc_filled += len;
            if self.app_desc_filled == ESP_APP_DESC_SIZE {
                EspAppMetadata::parse(&self.app_desc)?;
            }
        }

        while self.erased_until < end {
            let erase_end = self
                .erased_until
                .checked_add(FlashStorage::SECTOR_SIZE)
                .ok_or(OtaSinkError::OutOfBounds)?;
            if erase_end > self.capacity {
                return Err(OtaSinkError::OutOfBounds);
            }
            // Sector erases run with the cache and interrupts disabled, so the
            // executor cannot pet the watchdog for us here.
            pet_watchdog();
            self.region
                .erase(self.erased_until, erase_end)
                .map_err(OtaSinkError::Flash)?;
            self.erased_until = erase_end;
        }

        Storage::write(&mut self.region, offset, bytes).map_err(OtaSinkError::Flash)?;
        self.written_until = end;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum FirmwareUpdateError {
    Ota(PartitionError),
    Image(microtun_mcuboot::Error),
    Flash(OtaSinkError),
    Transfer(TransferError),
}

impl From<PartitionError> for FirmwareUpdateError {
    fn from(error: PartitionError) -> Self {
        Self::Ota(error)
    }
}

impl From<TransferError> for FirmwareUpdateError {
    fn from(error: TransferError) -> Self {
        Self::Transfer(error)
    }
}

impl From<ImageTransferError<OtaSinkError>> for FirmwareUpdateError {
    fn from(error: ImageTransferError<OtaSinkError>) -> Self {
        match error {
            ImageTransferError::Transfer(error) => Self::Transfer(error),
            ImageTransferError::Image(error) => Self::Image(error),
            ImageTransferError::Sink(error) => Self::Flash(error),
        }
    }
}

impl From<StoredImageError<PartitionError>> for FirmwareUpdateError {
    fn from(error: StoredImageError<PartitionError>) -> Self {
        match error {
            StoredImageError::Image(error) => Self::Image(error),
            StoredImageError::Read(error) => Self::Ota(error),
        }
    }
}

pub(crate) fn firmware_update_error_text(error: &FirmwareUpdateError) -> &'static str {
    match error {
        FirmwareUpdateError::Ota(_) => "ESP OTA metadata or partition operation failed",
        FirmwareUpdateError::Image(microtun_mcuboot::Error::VersionTooLow) => {
            "firmware version is older than the running image (anti-rollback)"
        }
        FirmwareUpdateError::Image(microtun_mcuboot::Error::StoredImageInvalid) => {
            "flash read-back does not reproduce the signed image digest"
        }
        FirmwareUpdateError::Image(_) => "MCUboot image validation failed",
        FirmwareUpdateError::Flash(OtaSinkError::InvalidEspImage) => {
            "MCUboot payload is not an ESP application image"
        }
        FirmwareUpdateError::Flash(OtaSinkError::InvalidEspAppDesc) => {
            "ESP application metadata is missing or invalid"
        }
        FirmwareUpdateError::Flash(OtaSinkError::NonSequentialWrite) => {
            "firmware payload was not streamed sequentially"
        }
        FirmwareUpdateError::Flash(OtaSinkError::OutOfBounds) => "firmware does not fit OTA slot",
        FirmwareUpdateError::Flash(OtaSinkError::Flash(_)) => "flash write failed",
        FirmwareUpdateError::Transfer(error) => error,
    }
}

pub(crate) fn log_firmware_update_error(error: &FirmwareUpdateError) {
    match error {
        FirmwareUpdateError::Ota(inner) => warn!("firmware OTA error: {:?}", inner),
        FirmwareUpdateError::Image(inner) => warn!("firmware MCUboot error: {:?}", inner),
        FirmwareUpdateError::Flash(OtaSinkError::Flash(inner)) => {
            warn!("firmware flash error: {:?}", inner)
        }
        _ => warn!("firmware update error: {:?}", error),
    }
}

pub(crate) async fn receive_firmware_update<T>(
    io: &mut T,
    flash: &mut FlashStorage<'static>,
) -> Result<(EspAppMetadata, AppPartitionSubType), FirmwareUpdateError>
where
    T: Read + Write + ?Sized,
{
    let (metadata, slot) = {
        let mut partition_buffer = [0u8; PARTITION_TABLE_MAX_LEN];
        let mut updater = OtaUpdater::new(flash, &mut partition_buffer)?;
        let (region, slot) = updater.next_partition()?;
        let max_image_size = region.partition_size() as u32;
        let mut sink = EspOtaSink::new(region);
        let mut verifier = StreamingVerifier::new(
            *FIRMWARE_PUBLIC_KEY,
            McubootPolicy::from_imgtool_names(
                FIRMWARE_VENDOR_ID,
                FIRMWARE_COMPONENT_ID,
                max_image_size,
                FIRMWARE_MCUBOOT_VERSION,
            ),
        )
        .map_err(FirmwareUpdateError::Image)?;

        receive_signed_image(io, &mut verifier, &mut sink).await?;
        let verified = verifier.finish().map_err(FirmwareUpdateError::Image)?;

        // Streaming verification only proves the bytes on the wire were
        // authentic. Rebuild the signed digest from what the partition actually
        // holds before the slot can become bootable.
        verify_stored_image(sink.region_mut(), &verified)?;

        // The descriptor sits inside the signed payload, so the version and
        // secure-version reported to the operator are authentic. They are
        // reported only: anti-rollback is enforced once, by the signed MCUboot
        // image version above. Meaningful enforcement of `secure_version`
        // belongs in the bootloader against an eFuse floor
        // (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`), not here.
        let metadata = sink.app_metadata().map_err(FirmwareUpdateError::Flash)?;
        let version = verified.header.version;
        info!(
            "firmware read-back verified in {} (version={}.{}.{}+{})",
            ota_slot_name(slot),
            version.major,
            version.minor,
            version.revision,
            version.build
        );
        (metadata, slot)
    };

    // Stage the trial state into the otadata entry that activation will claim,
    // so that selecting the new slot and marking it NEW is a single write.
    prime_next_ota_state(flash, OtaImageState::New)?;

    let mut partition_buffer = [0u8; PARTITION_TABLE_MAX_LEN];
    let mut updater = OtaUpdater::new(flash, &mut partition_buffer)?;
    updater.activate_next_partition()?;
    // Redundant given the priming above, but harmless and keeps the state
    // correct if the entry ever has to be rewritten.
    updater.set_current_ota_state(OtaImageState::New)?;
    Ok((metadata, slot))
}
