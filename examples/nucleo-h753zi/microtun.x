/*
 * Keep the final 128 KiB STM32H753 flash sector out of the firmware image.
 * The portable 4 KiB MTUN record is written at 0x081e0000, but the entire
 * erase sector must remain unused by application code.
 */
PROVIDE(__microtun_provision_start = 0x081e0000);
ASSERT(__sidata + SIZEOF(.data) <= __microtun_provision_start,
       "firmware image overlaps the reserved microtun provisioning sector");
