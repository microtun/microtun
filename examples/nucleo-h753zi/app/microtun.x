/* STM32H753 Embassy Boot application checks.
 *
 * The complete physical flash map is defined once in memory.x and shared with
 * the first-stage bootloader. This script only enforces application-specific
 * link constraints.
 */
ASSERT(ORIGIN(FLASH) == ORIGIN(ACTIVE),
       "application FLASH must select the ACTIVE partition");
ASSERT(LENGTH(FLASH) == LENGTH(ACTIVE),
       "application FLASH length must match the ACTIVE partition");
ASSERT(__sidata + SIZEOF(.data) <= __microtun_firmware_slot_end,
       "firmware image exceeds the STM32 Embassy Boot ACTIVE slot");
