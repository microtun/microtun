//! NUCLEO-H753ZI firmware slot handling.
//!
//! The TELNET/YMODEM/MCUboot transport lives in
//! `microtun_examples_common::firmware`; what remains here is the Embassy Boot
//! state machine and the flash sink over the DFU partition.

use defmt::warn;
use embassy_boot::{AlignedBuffer, BlockingFirmwareState, State};
use embassy_net::tcp::TcpSocket;
use embassy_stm32::flash::{Blocking, Error as FlashError, Flash, WRITE_SIZE};
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
pub(crate) use microtun_examples_common::firmware::{
    FirmwareStatus, receive_ymodem_buffer, telnet_write_data,
};
use microtun_examples_common::firmware::{
    ImageTransferError, TransferError, receive_signed_image, transfer_error_text,
};
use microtun_mcuboot::{
    ImageVersion, PayloadSink, Policy as McubootPolicy, StoredImageError, StreamingVerifier,
    VerifiedImage, verify_stored_image,
};

use crate::pet_watchdog;

const FIRMWARE_VENDOR_ID: &str = "firmware.microtun.dev";
const FIRMWARE_COMPONENT_ID: &str = "nucleo-h753zi";
const FIRMWARE_PUBLIC_KEY: &[u8; 32] =
    include_bytes!(concat!(env!("OUT_DIR"), "/firmware-public-key.bin"));

// Anti-rollback floor, emitted by build.rs from this app's Cargo package
// SemVer. Sign update envelopes with the same version via `imgtool sign -v
// <x.y.z>`; an older signed MCUboot header version is refused.
include!(concat!(env!("OUT_DIR"), "/firmware-version.rs"));

// Embassy Boot owns rollback state and swaps ACTIVE/DFU pages power-fail-safely.
// H753 sectors are 128 KiB. The application is linked at 0x0802_0000:
//   bank1 s0: bootloader (128 KiB)
//   bank1 s1..s6: ACTIVE (768 KiB)
//   bank1 s7: boot state (128 KiB)
//   bank2 s0..s6: DFU (896 KiB; one sector larger than ACTIVE)
//   bank2 s7: provisioning (128 KiB)
pub(crate) const DFU_SLOT_OFFSET: u32 = 0x0010_0000;
pub(crate) const FIRMWARE_SLOT_SIZE: u32 = 0x000c_0000; // 768 KiB ACTIVE payload
const DFU_SLOT_SIZE: u32 = 0x000e_0000; // ACTIVE + one scratch sector
const BOOT_STATE_OFFSET: u32 = 0x000e_0000;
const BOOT_STATE_SIZE: u32 = 0x0002_0000;
const FLASH_SECTOR_SIZE: u32 = 0x0002_0000;
const STM32_APP_BASE: u32 = 0x0802_0000;
const STM32_APP_END: u32 = STM32_APP_BASE + FIRMWARE_SLOT_SIZE;

struct BootStatePartition<'a, 'd> {
    flash: &'a mut Flash<'d, Blocking>,
}

impl ErrorType for BootStatePartition<'_, '_> {
    type Error = FlashError;
}

impl ReadNorFlash for BootStatePartition<'_, '_> {
    const READ_SIZE: usize = 1;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        if offset
            .checked_add(bytes.len() as u32)
            .is_none_or(|end| end > BOOT_STATE_SIZE)
        {
            return Err(FlashError::Size);
        }
        self.flash.blocking_read(BOOT_STATE_OFFSET + offset, bytes)
    }

    fn capacity(&self) -> usize {
        BOOT_STATE_SIZE as usize
    }
}

impl NorFlash for BootStatePartition<'_, '_> {
    const WRITE_SIZE: usize = WRITE_SIZE;
    const ERASE_SIZE: usize = FLASH_SECTOR_SIZE as usize;

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        if offset
            .checked_add(bytes.len() as u32)
            .is_none_or(|end| end > BOOT_STATE_SIZE)
        {
            return Err(FlashError::Size);
        }
        pet_watchdog();
        self.flash.blocking_write(BOOT_STATE_OFFSET + offset, bytes)
    }

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        if to > BOOT_STATE_SIZE || from > to {
            return Err(FlashError::Size);
        }
        pet_watchdog();
        self.flash
            .blocking_erase(BOOT_STATE_OFFSET + from, BOOT_STATE_OFFSET + to)
    }
}

fn boot_state(flash: &mut Flash<'_, Blocking>) -> Result<State, FirmwareUpdateError> {
    let mut aligned = AlignedBuffer([0u8; WRITE_SIZE]);
    let mut state = BlockingFirmwareState::new(BootStatePartition { flash }, aligned.as_mut());
    state
        .get_state()
        .map_err(|_| FirmwareUpdateError::BootState)
}

pub(crate) fn prepare_firmware_boot(
    flash: &mut Flash<'_, Blocking>,
) -> Result<FirmwareStatus, FirmwareUpdateError> {
    let mut aligned = AlignedBuffer([0u8; WRITE_SIZE]);
    let mut state = BlockingFirmwareState::new(BootStatePartition { flash }, aligned.as_mut());
    let current = state
        .get_state()
        .map_err(|_| FirmwareUpdateError::BootState)?;
    match current {
        State::Boot => Ok(FirmwareStatus {
            slot: "active",
            state: "valid",
            trial: false,
        }),
        State::Swap => Ok(FirmwareStatus {
            slot: "active",
            state: "pending-verify",
            trial: true,
        }),
        State::Revert => {
            state
                .mark_booted()
                .map_err(|_| FirmwareUpdateError::BootState)?;
            Ok(FirmwareStatus {
                slot: "active",
                state: "recovered",
                trial: false,
            })
        }
        State::DfuDetach => Ok(FirmwareStatus {
            slot: "active",
            state: "dfu",
            trial: false,
        }),
    }
}

pub(crate) fn confirm_firmware_boot(
    flash: &mut Flash<'_, Blocking>,
) -> Result<FirmwareStatus, FirmwareUpdateError> {
    let mut aligned = AlignedBuffer([0u8; WRITE_SIZE]);
    let mut state = BlockingFirmwareState::new(BootStatePartition { flash }, aligned.as_mut());
    state
        .mark_booted()
        .map_err(|_| FirmwareUpdateError::BootState)?;
    Ok(FirmwareStatus {
        slot: "active",
        state: "valid",
        trial: false,
    })
}

fn mark_firmware_updated(flash: &mut Flash<'_, Blocking>) -> Result<(), FirmwareUpdateError> {
    let mut aligned = AlignedBuffer([0u8; WRITE_SIZE]);
    let mut state = BlockingFirmwareState::new(BootStatePartition { flash }, aligned.as_mut());
    state
        .mark_updated()
        .map_err(|_| FirmwareUpdateError::BootState)
}

#[derive(defmt::Format)]
pub(crate) enum Stm32SinkError {
    Flash(FlashError),
    InvalidVectorTable,
    NonSequentialWrite,
    OutOfBounds,
}

struct Stm32FirmwareSink<'a, 'd> {
    flash: &'a mut Flash<'d, Blocking>,
    logical_offset: u32,
    written_offset: u32,
    erased_until: u32,
    pending: [u8; WRITE_SIZE],
    pending_len: usize,
    vector: [u8; 8],
    vector_len: usize,
    vector_checked: bool,
}

impl<'a, 'd> Stm32FirmwareSink<'a, 'd> {
    fn new(flash: &'a mut Flash<'d, Blocking>) -> Self {
        // No erase happens here. The DFU partition holds the copy Embassy Boot
        // reverts to, and erasing all 896 KiB up front — before a single byte
        // of the transfer has arrived — both destroys that copy and stalls the
        // executor for seconds while the tunnel carrying the update times out.
        // Sectors are erased lazily as the stream reaches them instead.
        Self {
            flash,
            logical_offset: 0,
            written_offset: 0,
            erased_until: 0,
            pending: [0xff; WRITE_SIZE],
            pending_len: 0,
            vector: [0; 8],
            vector_len: 0,
            vector_checked: false,
        }
    }

    fn capture_vector(&mut self, bytes: &[u8]) -> Result<(), Stm32SinkError> {
        if self.vector_checked || self.vector_len == self.vector.len() {
            return Ok(());
        }
        let take = (self.vector.len() - self.vector_len).min(bytes.len());
        self.vector[self.vector_len..self.vector_len + take].copy_from_slice(&bytes[..take]);
        self.vector_len += take;
        if self.vector_len == self.vector.len() {
            self.validate_vector()?;
            self.vector_checked = true;
        }
        Ok(())
    }

    fn validate_vector(&self) -> Result<(), Stm32SinkError> {
        let initial_sp = u32::from_le_bytes(self.vector[0..4].try_into().unwrap());
        let reset = u32::from_le_bytes(self.vector[4..8].try_into().unwrap());
        let stack_in_ram = (0x2000_0000..0x4000_0000).contains(&initial_sp);
        let reset_addr = reset & !1;
        let reset_in_image =
            reset & 1 == 1 && (STM32_APP_BASE..STM32_APP_END).contains(&reset_addr);
        if stack_in_ram && reset_in_image {
            Ok(())
        } else {
            Err(Stm32SinkError::InvalidVectorTable)
        }
    }

    /// Erase forward so that everything below `end` is programmable.
    ///
    /// A 128 KiB H7 sector erase takes on the order of a second and cannot
    /// yield, so the watchdog is petted around each one.
    fn ensure_erased(&mut self, end: u32) -> Result<(), Stm32SinkError> {
        while self.erased_until < end {
            let erase_end = self
                .erased_until
                .checked_add(FLASH_SECTOR_SIZE)
                .ok_or(Stm32SinkError::OutOfBounds)?;
            if erase_end > DFU_SLOT_SIZE {
                return Err(Stm32SinkError::OutOfBounds);
            }
            pet_watchdog();
            self.flash
                .blocking_erase(
                    DFU_SLOT_OFFSET + self.erased_until,
                    DFU_SLOT_OFFSET + erase_end,
                )
                .map_err(Stm32SinkError::Flash)?;
            self.erased_until = erase_end;
            pet_watchdog();
        }
        Ok(())
    }

    fn write_aligned(&mut self, bytes: &[u8]) -> Result<(), Stm32SinkError> {
        debug_assert_eq!(bytes.len() % WRITE_SIZE, 0);
        let end = self
            .written_offset
            .checked_add(bytes.len() as u32)
            .ok_or(Stm32SinkError::OutOfBounds)?;
        if end > FIRMWARE_SLOT_SIZE {
            return Err(Stm32SinkError::OutOfBounds);
        }
        self.ensure_erased(end)?;
        self.flash
            .blocking_write(DFU_SLOT_OFFSET + self.written_offset, bytes)
            .map_err(Stm32SinkError::Flash)?;
        self.written_offset = end;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Stm32SinkError> {
        if self.vector_len != self.vector.len() {
            return Err(Stm32SinkError::InvalidVectorTable);
        }
        if !self.vector_checked {
            self.validate_vector()?;
            self.vector_checked = true;
        }
        if self.pending_len != 0 {
            self.pending[self.pending_len..].fill(0xff);
            let block = self.pending;
            self.write_aligned(&block)?;
            self.pending_len = 0;
        }
        Ok(())
    }
}

impl PayloadSink for Stm32FirmwareSink<'_, '_> {
    type Error = Stm32SinkError;

    fn write(&mut self, offset: u32, mut bytes: &[u8]) -> Result<(), Self::Error> {
        if offset != self.logical_offset {
            return Err(Stm32SinkError::NonSequentialWrite);
        }
        let end = offset
            .checked_add(bytes.len() as u32)
            .ok_or(Stm32SinkError::OutOfBounds)?;
        if end > FIRMWARE_SLOT_SIZE {
            return Err(Stm32SinkError::OutOfBounds);
        }
        self.capture_vector(bytes)?;
        if self.pending_len != 0 {
            let take = (WRITE_SIZE - self.pending_len).min(bytes.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&bytes[..take]);
            self.pending_len += take;
            bytes = &bytes[take..];
            if self.pending_len == WRITE_SIZE {
                let block = self.pending;
                self.write_aligned(&block)?;
                self.pending_len = 0;
                self.pending.fill(0xff);
            }
        }
        let aligned_len = bytes.len() / WRITE_SIZE * WRITE_SIZE;
        if aligned_len != 0 {
            self.write_aligned(&bytes[..aligned_len])?;
            bytes = &bytes[aligned_len..];
        }
        if !bytes.is_empty() {
            self.pending[..bytes.len()].copy_from_slice(bytes);
            self.pending_len = bytes.len();
        }
        self.logical_offset = end;
        Ok(())
    }
}

/// Read-only view of the DFU partition at slot-relative offsets.
///
/// `verify_stored_image` reads the slot back through the standard
/// `ReadNorFlash` interface; this only rebases the offset onto the partition,
/// mirroring `BootStatePartition` above.
struct DfuPartition<'a, 'd> {
    flash: &'a mut Flash<'d, Blocking>,
}

impl ErrorType for DfuPartition<'_, '_> {
    type Error = FlashError;
}

impl ReadNorFlash for DfuPartition<'_, '_> {
    const READ_SIZE: usize = 1;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        if offset
            .checked_add(bytes.len() as u32)
            .is_none_or(|end| end > DFU_SLOT_SIZE)
        {
            return Err(FlashError::Size);
        }
        self.flash.blocking_read(DFU_SLOT_OFFSET + offset, bytes)
    }

    fn capacity(&self) -> usize {
        DFU_SLOT_SIZE as usize
    }
}

#[derive(defmt::Format)]
pub(crate) enum FirmwareUpdateError {
    Image(microtun_mcuboot::Error),
    Flash(Stm32SinkError),
    BootState,
    TrialPending,
    Transfer(TransferError),
}

impl From<TransferError> for FirmwareUpdateError {
    fn from(error: TransferError) -> Self {
        Self::Transfer(error)
    }
}

impl From<ImageTransferError<Stm32SinkError>> for FirmwareUpdateError {
    fn from(error: ImageTransferError<Stm32SinkError>) -> Self {
        match error {
            ImageTransferError::Transfer(error) => Self::Transfer(error),
            ImageTransferError::Image(error) => Self::Image(error),
            ImageTransferError::Sink(error) => Self::Flash(error),
        }
    }
}

impl From<StoredImageError<FlashError>> for FirmwareUpdateError {
    fn from(error: StoredImageError<FlashError>) -> Self {
        match error {
            StoredImageError::Image(error) => Self::Image(error),
            StoredImageError::Read(error) => Self::Flash(Stm32SinkError::Flash(error)),
        }
    }
}

pub(crate) fn firmware_update_error_text(error: &FirmwareUpdateError) -> &'static str {
    match error {
        FirmwareUpdateError::Image(microtun_mcuboot::Error::VersionTooLow) => {
            "firmware version is older than the running image (anti-rollback)"
        }
        FirmwareUpdateError::Image(microtun_mcuboot::Error::StoredImageInvalid) => {
            "flash read-back does not reproduce the signed image digest"
        }
        FirmwareUpdateError::Image(_) => "MCUboot image validation failed",
        FirmwareUpdateError::Flash(Stm32SinkError::InvalidVectorTable) => {
            "MCUboot payload is not a NUCLEO-H753ZI application image"
        }
        FirmwareUpdateError::Flash(Stm32SinkError::OutOfBounds) => {
            "firmware does not fit the 768 KiB active application slot"
        }
        FirmwareUpdateError::Flash(Stm32SinkError::NonSequentialWrite) => {
            "firmware payload was not streamed sequentially"
        }
        FirmwareUpdateError::Flash(Stm32SinkError::Flash(_)) => "flash write failed",
        FirmwareUpdateError::BootState => "Embassy Boot state update failed",
        FirmwareUpdateError::TrialPending => {
            "a trial image is still pending verification; reboot or confirm it first"
        }
        FirmwareUpdateError::Transfer(error) => transfer_error_text(*error),
    }
}

pub(crate) fn log_firmware_update_error(error: &FirmwareUpdateError) {
    match error {
        FirmwareUpdateError::BootState => warn!("firmware boot state error"),
        FirmwareUpdateError::Image(inner) => warn!("firmware MCUboot error: {:?}", inner),
        FirmwareUpdateError::Flash(Stm32SinkError::Flash(inner)) => {
            warn!("firmware flash error: {:?}", inner)
        }
        _ => warn!("firmware update error: {:?}", error),
    }
}

pub(crate) async fn receive_firmware_update(
    socket: &mut TcpSocket<'_>,
    flash: &mut Flash<'_, Blocking>,
) -> Result<(VerifiedImage, &'static str), FirmwareUpdateError> {
    let target_slot = "dfu";

    // Writing into DFU destroys the image Embassy Boot would revert to, so it
    // is only safe once the running image is confirmed. main.rs already starts
    // the shell after confirmation; this makes the invariant explicit rather
    // than relying on that ordering.
    if boot_state(flash)? != State::Boot {
        return Err(FirmwareUpdateError::TrialPending);
    }

    let mut sink = Stm32FirmwareSink::new(flash);
    let mut verifier = StreamingVerifier::new(
        *FIRMWARE_PUBLIC_KEY,
        McubootPolicy::from_imgtool_names(
            FIRMWARE_VENDOR_ID,
            FIRMWARE_COMPONENT_ID,
            FIRMWARE_SLOT_SIZE,
            FIRMWARE_MCUBOOT_VERSION,
        ),
    )
    .map_err(FirmwareUpdateError::Image)?;

    receive_signed_image(socket, &mut verifier, &mut sink).await?;

    let verified = verifier.finish().map_err(FirmwareUpdateError::Image)?;
    // Commit the trailing partial write word before reading anything back.
    sink.finish().map_err(FirmwareUpdateError::Flash)?;

    // Streaming verification only covers the bytes that arrived. Rebuild the
    // signed digest from what DFU actually holds before the bootloader is told
    // to swap.
    verify_stored_image(&mut DfuPartition { flash: &mut *flash }, &verified)?;

    mark_firmware_updated(flash)?;
    Ok((verified, target_slot))
}
