#![no_std]
#![no_main]

use core::cell::RefCell;

use cortex_m_rt::entry;
use embassy_boot_stm32::{BootLoader, BootLoaderConfig};
use embassy_stm32::flash::Flash;
use embassy_sync::blocking_mutex::{Mutex, raw::NoopRawMutex};

unsafe extern "C" {
    static __microtun_firmware_slot_start: u8;
}

// H753 internal flash has a 32-byte write granularity. This also satisfies
// embassy-boot's aligned swap-buffer requirements.
const SWAP_BUFFER_SIZE: usize = 32;

#[entry]
fn main() -> ! {
    let p = embassy_stm32::init(Default::default());
    let flash = Mutex::<NoopRawMutex, _>::new(RefCell::new(Flash::new_blocking(p.FLASH)));
    let config = BootLoaderConfig::from_linkerfile_blocking(&flash, &flash, &flash);

    // prepare() is power-fail-safe. State::Swap performs the trial swap; a
    // subsequent reset before the application calls mark_booted() causes the
    // next prepare() to revert ACTIVE to the previously confirmed image.
    let loader = BootLoader::prepare::<_, _, _, SWAP_BUFFER_SIZE>(config);

    // Safety: this takes the address of an absolute linker symbol and does not
    // dereference it.
    let active_app_start = core::ptr::addr_of!(__microtun_firmware_slot_start) as u32;

    // Safety: active_app_start is the linker-defined ACTIVE partition start from
    // the same memory.x used to link both this first stage and the application.
    unsafe { loader.load(active_app_start) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}
