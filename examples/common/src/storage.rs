//! Shared storage workflow for the embedded examples.
//!
//! Each board exposes its configuration partition through the standard
//! [`embedded_storage::nor_flash::NorFlash`] traits and implements [`FirmwareInstaller`] for its
//! board-specific OTA format. [`Storage`] owns the async mutex and the portable workflow around
//! those capabilities: configuration writes are validated before erase, serialized with every
//! other flash operation, then read back and validated exactly as the next boot will parse them.

use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use embedded_io_async::{Read, Write};
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use heapless::String;

use crate::configuration::{DeviceConfig, RECORD_SIZE, decode_record};

/// Detail lines shown to the operator after a firmware image has been accepted.
pub type FirmwareSummary = String<192>;

/// Board-specific firmware installation that cannot be expressed as a generic flash operation.
///
/// The transport is any async byte stream. Telnet/TCP is only one caller; keeping this boundary on
/// `embedded-io-async` avoids coupling the OTA verifier and board bootloader code to Embassy Net.
pub trait FirmwareInstaller {
    /// Receive, verify, and arm a board-specific firmware image.
    async fn install_firmware<T>(&mut self, io: &mut T) -> Result<FirmwareSummary, &'static str>
    where
        T: Read + Write + ?Sized;
}

/// Serialized access to one board's flash-backed storage.
///
/// The backend itself is a view of the configuration partition implementing the upstream NOR-flash
/// traits. The same value is used in setup and operational mode, so Telnet, the reset button, OTA
/// confirmation, and any future flash user all share one obvious lock.
pub struct Storage<B> {
    backend: Mutex<CriticalSectionRawMutex, B>,
}

impl<B> Storage<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend: Mutex::new(backend),
        }
    }

    /// Run one synchronous board-specific operation while holding the storage lock.
    ///
    /// This is intentionally small and is mainly for bootloader-specific confirmation steps that
    /// do not belong in the generic Telnet workflow.
    pub async fn with_backend<T>(&self, operation: impl FnOnce(&mut B) -> T) -> T {
        let mut backend = self.backend.lock().await;
        operation(&mut *backend)
    }
}

impl<B: ReadNorFlash> Storage<B> {
    /// Read and decode the persisted configuration record.
    pub async fn load_config(
        &self,
        record: &mut [u8; RECORD_SIZE],
    ) -> Result<Option<DeviceConfig>, &'static str> {
        let mut backend = self.backend.lock().await;
        backend
            .read(0, record)
            .map_err(|_| "flash operation failed")?;
        Ok(decode_record(record))
    }
}

impl<B: NorFlash> Storage<B> {
    /// Erase the complete configuration partition.
    pub async fn erase_config(&self) -> Result<(), &'static str> {
        let mut backend = self.backend.lock().await;
        let capacity = backend.capacity() as u32;
        backend
            .erase(0, capacity)
            .map_err(|_| "flash operation failed")
    }

    /// Persist and verify one fully encoded configuration record.
    pub async fn store_config(&self, record: &mut [u8; RECORD_SIZE]) -> Result<(), &'static str> {
        // Validate before taking the destructive step so the existing configuration remains
        // recoverable until the replacement has passed the same decoder used at boot.
        decode_record(record).ok_or("invalid config")?;

        let mut backend = self.backend.lock().await;
        let capacity = backend.capacity() as u32;
        backend
            .erase(0, capacity)
            .map_err(|_| "flash operation failed")?;
        backend
            .write(0, record)
            .map_err(|_| "flash operation failed")?;

        record.fill(0);
        backend
            .read(0, record)
            .map_err(|_| "flash operation failed")?;
        decode_record(record).ok_or("flash verification failed")?;
        Ok(())
    }
}

impl<B: FirmwareInstaller> Storage<B> {
    /// Receive, verify, and arm a firmware image while holding exclusive flash access.
    pub async fn install_firmware<T>(&self, io: &mut T) -> Result<FirmwareSummary, &'static str>
    where
        T: Read + Write + ?Sized,
    {
        let mut backend = self.backend.lock().await;
        backend.install_firmware(io).await
    }
}
