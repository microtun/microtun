//! ESP32-C6 storage adapter for the shared example workflow.
//!
//! `examples/common` owns synchronization and the configuration write/verify lifecycle. This
//! module exposes the ESP configuration partition through the standard `embedded-storage`
//! NOR-flash traits and implements the board-specific ESP-IDF OTA operation.

use embedded_io_async::{Read, Write};
use embedded_storage::nor_flash::{
    ErrorType, NorFlash, NorFlashErrorKind, ReadNorFlash, check_erase, check_read, check_write,
};
use esp_storage::FlashStorage;
use log::info;
use microtun_examples_common::{
    configuration::RECORD_SIZE,
    storage::{FirmwareInstaller, FirmwareSummary, Storage as CommonStorage},
};
use static_cell::StaticCell;

use crate::{
    CONFIGURATION_ADDRESS,
    firmware::{
        firmware_update_error_text, log_firmware_update_error, ota_slot_name,
        receive_firmware_update,
    },
    pet_watchdog,
};

pub(crate) type Storage = CommonStorage<BoardStorage>;

/// One configuration-record scratch buffer for the whole boot.
///
/// It is first used to read and decode flash, then reused by Telnet as the YMODEM receive area,
/// encoded record, write buffer, and read-back verification buffer.
pub(crate) static CONFIGURATION_BUFFER: StaticCell<[u8; RECORD_SIZE]> = StaticCell::new();

/// A configuration-partition view over the board's full flash handle.
///
/// Offsets exposed through `ReadNorFlash`/`NorFlash` are relative to the 4 KiB Microtun
/// configuration partition, while firmware installation can still access the full flash handle.
pub(crate) struct BoardStorage {
    flash: FlashStorage<'static>,
}

impl BoardStorage {
    pub(crate) fn new(flash: FlashStorage<'static>) -> Self {
        Self { flash }
    }

    pub(crate) fn flash_mut(&mut self) -> &mut FlashStorage<'static> {
        &mut self.flash
    }
}

impl ErrorType for BoardStorage {
    type Error = NorFlashErrorKind;
}

impl ReadNorFlash for BoardStorage {
    const READ_SIZE: usize = <FlashStorage<'static> as ReadNorFlash>::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        check_read(self, offset, bytes.len())?;
        self.flash
            .read(CONFIGURATION_ADDRESS + offset, bytes)
            .map_err(|_| NorFlashErrorKind::Other)
    }

    fn capacity(&self) -> usize {
        RECORD_SIZE
    }
}

impl NorFlash for BoardStorage {
    const WRITE_SIZE: usize = <FlashStorage<'static> as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <FlashStorage<'static> as NorFlash>::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        check_erase(self, from, to)?;

        // Flash operations temporarily disable the cache/interrupt-driven executor, so feed the
        // hardware watchdog on both sides of the sector erase.
        pet_watchdog();
        let result = self
            .flash
            .erase(CONFIGURATION_ADDRESS + from, CONFIGURATION_ADDRESS + to)
            .map_err(|_| NorFlashErrorKind::Other);
        pet_watchdog();
        result
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        check_write(self, offset, bytes.len())?;
        self.flash
            .write(CONFIGURATION_ADDRESS + offset, bytes)
            .map_err(|_| NorFlashErrorKind::Other)
    }
}

impl FirmwareInstaller for BoardStorage {
    async fn install_firmware<T>(&mut self, io: &mut T) -> Result<FirmwareSummary, &'static str>
    where
        T: Read + Write + ?Sized,
    {
        let (metadata, slot) =
            receive_firmware_update(io, &mut self.flash)
                .await
                .map_err(|error| {
                    log_firmware_update_error(&error);
                    firmware_update_error_text(&error)
                })?;

        let version = metadata.version().unwrap_or("invalid");
        let project = metadata.project_name().unwrap_or("invalid");
        info!(
            "firmware update verified and activated: {} ({}, secure-version={}) -> {}",
            version,
            project,
            metadata.secure_version(),
            ota_slot_name(slot)
        );

        let mut summary = FirmwareSummary::new();
        core::fmt::Write::write_fmt(
            &mut summary,
            format_args!(
                "version: {}\r\nproject: {}\r\nsecure-version: {}\r\nslot: {}",
                version,
                project,
                metadata.secure_version(),
                ota_slot_name(slot)
            ),
        )
        .map_err(|_| "firmware summary too long")?;
        Ok(summary)
    }
}
