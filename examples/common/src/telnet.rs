//! The telnet front end: one accept loop, shared by every board and both shell modes.
//!
//! Setup and operational mode use the same accept loop and the same mutex-backed storage handle.
//! Board-specific configuration flash uses the standard `embedded-storage` NOR-flash traits;
//! only firmware installation remains a domain-specific capability. This module owns session flow,
//! YMODEM handoff, and connection-level cleanup.

use core::fmt;

use defmt_or_log::{info, warn};
use embassy_net::tcp::TcpSocket;
use embassy_time::{Duration, with_timeout};
use embedded_storage::nor_flash::NorFlash;
use microtun_cli::{
    Config as CliConfig, Dispatch, Error as CliError, ParserFamily, Session,
    telnet::write_fmt as telnet_write_fmt,
};

use crate::{
    cli::{TELNET_IDLE_TIMEOUT, TELNET_KEEP_ALIVE, TELNET_PORT, TELNET_PROMPT, TELNET_TCP_BUFFER},
    configuration::{CONFIG_INSTALLED, RECORD_SIZE, encode_record_in_place, record_payload_buffer},
    firmware::receive_ymodem_buffer,
    shell::ShellContext,
    storage::{FirmwareInstaller, Storage},
};

/// Scratch capacity for one operator-facing message.
///
/// Sized for the longest of them (firmware acceptance, below) with room to spare. It was four
/// different hand-picked numbers per board before, which meant a message that fit on one board
/// could be reported as a format overflow on the other.
const MESSAGE_CAP: usize = 320;

/// Maximum time to wait for the peer to acknowledge the TCP FIN before resetting.
const REBOOT_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Out-of-band action requested by a shell command.
///
/// Normal disconnect and `quit` need no action; these variants are handled only after the
/// line-oriented session has released the socket.
pub enum SessionAction {
    Reboot,
    ConfigInstall,
    ConfigClear,
    FirmwareUpdate,
}

/// Gracefully close the Telnet connection and reset the board. Never returns.
async fn reboot<C: ShellContext>(socket: &mut TcpSocket<'_>, shell: &C) -> ! {
    // `close()` queues a TCP FIN after any pending data. `flush()` then waits for the pending
    // data and FIN to leave the stack (and, for the FIN, for the peer to acknowledge it). Keep
    // the wait bounded so an unreachable client cannot hold a requested reboot indefinitely.
    socket.close();
    match with_timeout(REBOOT_CLOSE_TIMEOUT, socket.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!("telnet socket close before reboot failed: {:?}", error),
        Err(_) => warn!("telnet socket close before reboot timed out"),
    }
    shell.reset()
}

/// Write a closing message, gracefully close the Telnet connection, and reset the board.
async fn reboot_with<C: ShellContext>(
    socket: &mut TcpSocket<'_>,
    shell: &C,
    args: fmt::Arguments<'_>,
) -> ! {
    // Best-effort: the operator may already be gone, and rebooting matters more than telling
    // them about it.
    let _ = telnet_write_fmt::<MESSAGE_CAP, _>(socket, args).await;
    reboot(socket, shell).await
}

/// Report a recoverable failure. `false` means the socket is gone and the session must end.
async fn report(socket: &mut TcpSocket<'_>, reason: fmt::Arguments<'_>) -> bool {
    telnet_write_fmt::<MESSAGE_CAP, _>(
        socket,
        format_args!("\r\n{reason}\r\nreturning to shell\r\n"),
    )
    .await
    .is_ok()
}

async fn receive_configuration<B: NorFlash>(
    socket: &mut TcpSocket<'_>,
    storage: &Storage<B>,
    scratch: &mut [u8; RECORD_SIZE],
) -> Result<(), &'static str> {
    let len = receive_ymodem_buffer(socket, record_payload_buffer(scratch)).await?;
    encode_record_in_place(scratch, len).map_err(|_| "invalid configuration")?;
    storage.store_config(scratch).await
}

/// Serve the telnet shell forever.
///
/// Listens on [`ShellState::shell_stack`](crate::shell::ShellState::shell_stack): the tunnel's
/// inner interface once a tunnel exists, the physical interface while it does not. That is the
/// only thing that used to distinguish the operational accept loop from the setup one,
/// and the shell already knows the answer.
///
/// `configuration_scratch` is the single configuration record buffer shared with the boot-time
/// flash read. YMODEM receives directly into its payload area, then the header is encoded in
/// place before the same bytes are written and read back for verification. Keeping the buffer
/// in the caller's static budget makes the 4 KiB cost explicit in the map file.
pub async fn serve<P, C, B>(
    shell: &mut C,
    storage: &Storage<B>,
    configuration_scratch: &mut [u8; RECORD_SIZE],
    banner: &'static str,
) -> !
where
    C: ShellContext,
    P: ParserFamily,
    B: NorFlash + FirmwareInstaller,
    for<'a> <P as ParserFamily>::Parsed<'a>: Dispatch<C>,
{
    let mut rx = [0u8; TELNET_TCP_BUFFER];
    let mut tx = [0u8; TELNET_TCP_BUFFER];

    let state = shell.state();
    let stack = state.shell_stack();
    let device_id = state.identity.device_id();

    info!(
        "{} telnet shell: device={} listening on port {}",
        state.mode.name(),
        device_id.as_str(),
        TELNET_PORT
    );
    if let Some(config) = stack.config_v4() {
        // Logged as octets rather than as the `Ipv4Cidr` itself so the line renders identically
        // under the defmt and log backends.
        let address = config.address.address().octets();
        info!(
            "telnet shell address {}.{}.{}.{}",
            address[0], address[1], address[2], address[3]
        );
    }

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        // The shell may sit idle indefinitely, so use TCP-level liveness rather than an
        // application idle timeout: a healthy quiet client stays connected while a vanished or
        // reset client is eventually reclaimed.
        socket.set_keep_alive(Some(TELNET_KEEP_ALIVE));
        socket.set_timeout(Some(TELNET_IDLE_TIMEOUT));

        if let Err(error) = socket.accept(TELNET_PORT).await {
            warn!("telnet accept failed: {:?}", error);
            continue;
        }
        info!("telnet client connected");

        loop {
            *shell.pending_action() = None;
            let result = Session::<_, 160, 4, 256>::new(
                &mut socket,
                CliConfig::new(TELNET_PROMPT).banner(banner),
            )
            .serve::<P, _>(shell)
            .await;
            let Some(action) = shell.pending_action().take() else {
                match result {
                    Ok(()) | Err(CliError::Disconnected) => break,
                    Err(error) => warn!("telnet session ended with error: {:?}", error),
                }
                break;
            };

            // Each recoverable arm reports whether the socket survived the operation. Reboot
            // paths diverge, so their `!` simply coerces.
            let alive = match action {
                SessionAction::Reboot => reboot(&mut socket, shell).await,

                SessionAction::ConfigInstall => {
                    match receive_configuration(&mut socket, storage, configuration_scratch).await {
                        Ok(()) => {
                            info!("device configuration installed; rebooting");
                            reboot_with(
                                &mut socket,
                                shell,
                                format_args!("\r\n{CONFIG_INSTALLED}\r\n"),
                            )
                            .await
                        }
                        Err(error) => {
                            warn!("configuration install failed: {}", error);
                            report(
                                &mut socket,
                                format_args!("configuration install failed: {error}"),
                            )
                            .await
                        }
                    }
                }

                SessionAction::ConfigClear => match storage.erase_config().await {
                    Ok(()) => {
                        info!("device configuration cleared; rebooting");
                        reboot_with(
                            &mut socket,
                            shell,
                            format_args!("\r\nconfiguration cleared; rebooting\r\n"),
                        )
                        .await
                    }
                    Err(error) => {
                        warn!("configuration erase failed: {}", error);
                        report(
                            &mut socket,
                            format_args!("failed to clear configuration: {error}"),
                        )
                        .await
                    }
                },

                SessionAction::FirmwareUpdate => {
                    match storage.install_firmware(&mut socket).await {
                        Ok(summary) => {
                            info!("firmware update verified and activated; rebooting");
                            reboot_with(
                                &mut socket,
                                shell,
                                format_args!(
                                    "\r\nfirmware accepted\r\n{}\r\nrebooting\r\n",
                                    summary.as_str()
                                ),
                            )
                            .await
                        }
                        Err(error) => {
                            report(&mut socket, format_args!("firmware update failed: {error}"))
                                .await
                        }
                    }
                }
            };

            if !alive {
                break;
            }
        }

        socket.close();
        if let Err(error) = socket.flush().await {
            warn!("telnet socket close failed: {:?}", error);
        }
    }
}
