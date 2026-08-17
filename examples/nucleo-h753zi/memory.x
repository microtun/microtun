/* STM32H753ZI shared flash layout for the application and Embassy Boot first stage.
 *
 *   0x0800_0000..0x0801_FFFF  BOOTLOADER       128 KiB (bank 1 sector 0)
 *   0x0802_0000..0x080D_FFFF  ACTIVE           768 KiB (bank 1 sectors 1..6)
 *   0x080E_0000..0x080F_FFFF  STATE            128 KiB (bank 1 sector 7)
 *   0x0810_0000..0x081D_FFFF  DFU + scratch    896 KiB (bank 2 sectors 0..6)
 *   0x081E_0000..0x081F_FFFF  PROVISIONING     128 KiB (bank 2 sector 7)
 *
 * cortex-m-rt links sections through the FLASH region. The application uses
 * ACTIVE by default; the first stage passes --defsym=__microtun_link_bootloader=1
 * and therefore links FLASH over BOOTLOADER instead.
 */
MEMORY
{
  BOOTLOADER   (rx)  : ORIGIN = 0x08000000, LENGTH = 128K
  ACTIVE       (rx)  : ORIGIN = ORIGIN(BOOTLOADER) + LENGTH(BOOTLOADER), LENGTH = 768K
  STATE        (rx)  : ORIGIN = ORIGIN(ACTIVE) + LENGTH(ACTIVE), LENGTH = 128K
  DFU          (rx)  : ORIGIN = ORIGIN(STATE) + LENGTH(STATE), LENGTH = 896K
  PROVISIONING (rx)  : ORIGIN = ORIGIN(DFU) + LENGTH(DFU), LENGTH = 128K

  /* cortex-m-rt always links through FLASH. Select one of the regions above
   * without repeating its address or size.
   */
  FLASH        (rx)  : ORIGIN = DEFINED(__microtun_link_bootloader) ? ORIGIN(BOOTLOADER) : ORIGIN(ACTIVE),
                       LENGTH = DEFINED(__microtun_link_bootloader) ? LENGTH(BOOTLOADER) : LENGTH(ACTIVE)
  RAM          (rwx) : ORIGIN = 0x24000000, LENGTH = 512K
}

/* CPU-address bounds shared by the application checks and first stage. */
PROVIDE(__microtun_firmware_slot_start = ORIGIN(ACTIVE));
PROVIDE(__microtun_firmware_slot_end   = ORIGIN(ACTIVE) + LENGTH(ACTIVE));

/* embassy-boot-stm32 consumes offsets into the internal Flash driver rather
 * than CPU memory-map addresses. Derive those offsets from the shared map so
 * they cannot drift independently from the partition definitions above.
 */
__bootloader_active_start = ORIGIN(ACTIVE) - ORIGIN(BOOTLOADER);
__bootloader_active_end   = ORIGIN(ACTIVE) + LENGTH(ACTIVE) - ORIGIN(BOOTLOADER);
__bootloader_state_start  = ORIGIN(STATE) - ORIGIN(BOOTLOADER);
__bootloader_state_end    = ORIGIN(STATE) + LENGTH(STATE) - ORIGIN(BOOTLOADER);
__bootloader_dfu_start    = ORIGIN(DFU) - ORIGIN(BOOTLOADER);
__bootloader_dfu_end      = ORIGIN(DFU) + LENGTH(DFU) - ORIGIN(BOOTLOADER);

ASSERT(LENGTH(DFU) >= LENGTH(ACTIVE) + LENGTH(STATE),
       "DFU must provide ACTIVE plus at least one 128 KiB scratch sector");
ASSERT(ORIGIN(PROVISIONING) + LENGTH(PROVISIONING) == 0x08200000,
       "shared layout must fit exactly in the STM32H753 2 MiB internal flash");
