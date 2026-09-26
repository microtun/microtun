# ESP32-C6 bootloader

This directory builds the ESP-IDF second-stage bootloader used by the ESP32-C6
firmware. The current board profile is the ESP32-C6 PLC-V.

The build runs entirely in Docker using ESP-IDF 5.5.5. No local ESP-IDF installation is required.

## Build

From this directory, run:

```sh
docker buildx build \
    --file Dockerfile.boot \
    --output type=local,dest=target \
    .
```

The resulting bootloader image is written to:

```text
target/bootloader.bin
```

The sibling `../app/` project expects the bootloader at this location when creating or flashing the complete firmware image.

## What the build does

`Dockerfile.boot` creates a minimal ESP-IDF project targeting the ESP32-C6 and builds the standard ESP-IDF second-stage bootloader with application rollback support enabled:

```text
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
```

ESP-IDF eFuse anti-rollback is intentionally not enabled. Firmware version validation and rollback policy are handled separately by the application/update flow rather than using the ESP32-C6 secure-version eFuse counter.

The build uses:

```text
espressif/idf:v5.5.5
```

to keep the bootloader build reproducible and independent of the host's ESP-IDF installation.
