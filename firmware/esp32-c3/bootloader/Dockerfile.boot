FROM espressif/idf:v5.5.5 AS builder

SHELL ["/bin/bash", "-lc"]

WORKDIR /project

# ESP-IDF eFuse anti-rollback is intentionally not enabled. The application
# enforces authenticated MCUboot SemVer instead; see ../README.md.

RUN source "$IDF_PATH/export.sh" && \
    set -eux && \
    \
    printf '%s\n' \
        'cmake_minimum_required(VERSION 3.16)' \
        'include($ENV{IDF_PATH}/tools/cmake/project.cmake)' \
        'project(bootloader_build)' \
        > CMakeLists.txt && \
    \
    idf.py set-target esp32c3 && \
    \
    sed -i \
        -e '/^CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=/d' \
        -e '/^# CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE is not set$/d' \
        sdkconfig && \
    printf '\nCONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n' >> sdkconfig && \
    \
    idf.py reconfigure && \
    \
    grep -qx 'CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y' sdkconfig && \
    \
    idf.py bootloader && \
    \
    test -s build/bootloader/bootloader.bin && \
    cp build/bootloader/bootloader.bin /bootloader.bin && \
    sha256sum /bootloader.bin

FROM scratch AS artifact

COPY --from=builder /bootloader.bin /bootloader.bin