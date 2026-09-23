//! Nucleo storage adapter for the shared example workflow.
//!
//! `examples/common` owns synchronization and the configuration write/verify lifecycle. This
//! module exposes the linker-defined configuration partition through the standard
//! `embedded-storage` NOR-flash traits and implements the board-specific MCUboot operation.

use defmt::info;
use embassy_stm32::flash::{Blocking, Flash, MAX_ERASE_SIZE, WRITE_SIZE};
use embedded_io_async::{Read, Write};
use embedded_storage::nor_flash::{
    ErrorType, NorFlash, NorFlashErrorKind, ReadNorFlash, check_erase, check_read, check_write,
};
use microtun_examples_common::{
    configuration::RECORD_SIZE,
    storage::{FirmwareInstaller, FirmwareSummary, Storage as CommonStorage},
};
use static_cell::StaticCell;

use crate::{
    firmware::{
        self, firmware_update_error_text, log_firmware_update_error, receive_firmware_update,
    },
    pet_watchdog,
};

pub(crate) type Storage = CommonStorage<BoardStorage>;

/// One scratch buffer for the whole boot: load/decode first, then Telnet receive/write/verify.
pub(crate) static CONFIGURATION_BUFFER: StaticCell<[u8; RECORD_SIZE]> = StaticCell::new();

/// A configuration-partition view over the board's full internal flash handle.
pub(crate) struct BoardStorage {
    flash: Flash<'static, Blocking>,
}

impl BoardStorage {
    pub(crate) fn new(flash: Flash<'static, Blocking>) -> Self {
        Self { flash }
    }

    pub(crate) fn flash_mut(&mut self) -> &mut Flash<'static, Blocking> {
        &mut self.flash
    }
}

impl ErrorType for BoardStorage {
    type Error = NorFlashErrorKind;
}

impl ReadNorFlash for BoardStorage {
    const READ_SIZE: usize = 1;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        check_read(self, offset, bytes.len())?;
        self.flash
            .blocking_read(firmware::configuration().flash_offset() + offset, bytes)
            .map_err(|_| NorFlashErrorKind::Other)
    }

    fn capacity(&self) -> usize {
        firmware::configuration().len() as usize
    }
}

impl NorFlash for BoardStorage {
    const WRITE_SIZE: usize = WRITE_SIZE;
    const ERASE_SIZE: usize = MAX_ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        check_erase(self, from, to)?;
        let base = firmware::configuration().flash_offset();

        pet_watchdog();
        let result = self
            .flash
            .blocking_erase(base + from, base + to)
            .map_err(|_| NorFlashErrorKind::Other);
        pet_watchdog();
        result
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        check_write(self, offset, bytes.len())?;
        self.flash
            .blocking_write(firmware::configuration().flash_offset() + offset, bytes)
            .map_err(|_| NorFlashErrorKind::Other)
    }
}

impl FirmwareInstaller for BoardStorage {
    async fn install_firmware<T>(&mut self, io: &mut T) -> Result<FirmwareSummary, &'static str>
    where
        T: Read + Write + ?Sized,
    {
        let (verified, slot) =
            receive_firmware_update(io, &mut self.flash)
                .await
                .map_err(|error| {
                    log_firmware_update_error(&error);
                    firmware_update_error_text(&error)
                })?;

        let version = verified.header.version;
        info!(
            "firmware update verified and activated: {}.{}.{}+{} -> {}",
            version.major, version.minor, version.revision, version.build, slot
        );

        let mut summary = FirmwareSummary::new();
        core::fmt::Write::write_fmt(
            &mut summary,
            format_args!(
                "version: {}.{}.{}+{}\r\nslot: {}",
                version.major, version.minor, version.revision, version.build, slot
            ),
        )
        .map_err(|_| "firmware summary too long")?;
        Ok(summary)
    }
}
