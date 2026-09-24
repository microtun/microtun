//! Portable shell state and the command set shared by every embedded firmware target.
//!
//! Each board has one shell type for both setup and operational mode. [`ShellState`] is the one
//! portable state value shared by those shells; hardware behavior such as temperature, memory,
//! identify LEDs, and reset stays behind [`ShellContext`]. Board-specific commands such as `net`
//! stay in the board crate and are joined to [`CommonCommand`] with `#[command(flatten)]`.

use embassy_net::Stack;
use embassy_time::Instant as EmbassyInstant;
use embedded_io_async::Write as AsyncWrite;
use microtun_cli::{Error as CliError, ErrorKind, Subcommand, ValueEnum};
use microtun_embassy::{TunnelStatus, core::key::encode_key};

use crate::{
    board::SETUP_IDENTIFY_SECONDS,
    cli::{
        DEFAULT_PING_COUNT, PingIface, SYS_TABLE, SysField, Table, TunnelAction,
        field as cli_field, line as cli_line, ping as cli_ping, println as cli_println,
        time as cli_time, time_field as cli_time_field, write_tunnel_status,
    },
    configuration::DeviceIdentity,
    firmware::FirmwareStatus,
    telnet::SessionAction,
};

const YMODEM_READY: &str = "MICROTUN-YMODEM-1K READY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Setup,
    Operational,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Operational => "operational",
        }
    }

    pub const fn configuration_state(self) -> &'static str {
        match self {
            Self::Setup => "missing",
            Self::Operational => "present",
        }
    }
}

/// Portable state used by the common shell commands.
///
/// The board shell stores one of these directly. [`ShellContext::state`] may return a copy with a
/// freshly sampled wall clock, so command dispatch does not need a second metadata/state layer.
#[derive(Clone, Copy)]
pub struct ShellState {
    pub mode: Mode,
    pub model: &'static str,
    pub firmware_version: &'static str,
    pub identity: DeviceIdentity,
    pub reset_reason: &'static str,
    pub outer_stack: Stack<'static>,
    pub tunnel_stack: Option<Stack<'static>>,
    pub tunnel_status: Option<TunnelStatus<'static>>,
    pub unix_time: Option<(u64, u32)>,
    pub firmware: FirmwareStatus,
}

impl ShellState {
    pub fn setup(
        model: &'static str,
        firmware_version: &'static str,
        identity: DeviceIdentity,
        reset_reason: &'static str,
        outer_stack: Stack<'static>,
        firmware: FirmwareStatus,
    ) -> Self {
        Self {
            mode: Mode::Setup,
            model,
            firmware_version,
            identity,
            reset_reason,
            outer_stack,
            tunnel_stack: None,
            tunnel_status: None,
            unix_time: None,
            firmware,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn operational(
        model: &'static str,
        firmware_version: &'static str,
        identity: DeviceIdentity,
        reset_reason: &'static str,
        outer_stack: Stack<'static>,
        tunnel_stack: Stack<'static>,
        tunnel_status: TunnelStatus<'static>,
        firmware: FirmwareStatus,
    ) -> Self {
        Self {
            mode: Mode::Operational,
            model,
            firmware_version,
            identity,
            reset_reason,
            outer_stack,
            tunnel_stack: Some(tunnel_stack),
            tunnel_status: Some(tunnel_status),
            unix_time: None,
            firmware,
        }
    }

    pub fn with_unix_time(mut self, unix_time: Option<(u64, u32)>) -> Self {
        self.unix_time = unix_time;
        self
    }

    pub fn shell_stack(&self) -> Stack<'static> {
        self.tunnel_stack.unwrap_or(self.outer_stack)
    }
}

/// Board-facing behavior needed by the common command set.
pub trait ShellContext {
    /// Snapshot the portable state. Boards with a clock can update `unix_time` in this copy.
    fn state(&self) -> ShellState;

    async fn write_temperature<W>(
        &mut self,
        out: &mut W,
        table: Option<Table>,
    ) -> Result<(), CliError>
    where
        W: AsyncWrite<Error = ErrorKind> + ?Sized;

    async fn write_memory<W>(&mut self, out: &mut W, table: Option<Table>) -> Result<(), CliError>
    where
        W: AsyncWrite<Error = ErrorKind> + ?Sized;

    async fn identify(&mut self);

    fn reset(&self) -> !;

    /// Requested out-of-band action for the Telnet loop, if any.
    fn pending_action(&mut self) -> &mut Option<SessionAction>;

    fn request_action(&mut self, action: SessionAction) {
        *self.pending_action() = Some(action);
    }
}

/// The commands shared by every board and both shell modes.
///
/// Joined into a board's own command set with `#[command(flatten)]`, which splices these names
/// into the board's table without nesting them under a prefix.
#[derive(Debug, Subcommand)]
pub enum CommonCommand {
    /// Show system information.
    Sys {
        #[arg(value_enum, value_name = "FIELD")]
        field: Option<SysField>,
    },

    /// Ping an address.
    Ping {
        /// Interface to use.
        #[arg(value_enum, value_name = "IFACE")]
        iface: PingIface,
        /// IPv4 or IPv6 address to ping.
        #[arg(value_name = "ADDR")]
        addr: core::net::IpAddr,
        /// Number of echo requests to send (1-16).
        #[arg(value_name = "COUNT", default_value_t = DEFAULT_PING_COUNT)]
        count: u8,
    },

    /// Show tunnel status.
    Tunnel {
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<TunnelAction>,
    },

    /// Install or clear the persisted device configuration.
    Config {
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<ConfigAction>,
    },

    /// Show firmware status or install an update.
    Fw {
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<FirmwareAction>,
    },

    /// Identify this device by blinking its LED(s).
    Identify,

    /// Reboot the device.
    Reboot,

    /// Close this session.
    Quit,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ConfigAction {
    /// Erase the persisted device configuration and reboot.
    Clear,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum FirmwareAction {
    /// Show firmware update status.
    Show,
    /// Receive and install a signed MCUboot image using YMODEM-1K/CRC.
    Update,
}

pub const FW_TABLE: Table = Table::new(&["version", "slot"]);

const NO_TUNNEL: &str = "error: no tunnel in setup mode";

/// Dispatch one shared command against any shell.
///
/// This is the single body that replaced four near-identical copies.
pub async fn dispatch_common<C, W>(
    shell: &mut C,
    command: CommonCommand,
    out: &mut W,
) -> Result<(), CliError>
where
    C: ShellContext,
    W: AsyncWrite<Error = ErrorKind> + ?Sized,
{
    let state = shell.state();
    match command {
        CommonCommand::Sys { field: None } => {
            SYS_TABLE.field(out, "mode", state.mode.name()).await?;
            SYS_TABLE
                .field(out, "configuration", state.mode.configuration_state())
                .await?;
            SYS_TABLE.field(out, "board", state.model).await?;
            let device_id = state.identity.device_id();
            SYS_TABLE.field(out, "id", device_id.as_str()).await?;
            SYS_TABLE
                .field(out, "version", state.firmware_version)
                .await?;
            SYS_TABLE
                .field(out, "reset-reason", state.reset_reason)
                .await?;
            shell.write_temperature(out, Some(SYS_TABLE)).await?;
            SYS_TABLE
                .field_fmt(
                    out,
                    "uptime",
                    format_args!("{}ms", EmbassyInstant::now().as_millis()),
                )
                .await?;
            cli_time_field(out, SYS_TABLE, "time", state.unix_time).await?;
            shell.write_memory(out, Some(SYS_TABLE)).await?;
        }
        CommonCommand::Sys {
            field: Some(SysField::Mode),
        } => cli_println(out, state.mode.name()).await?,
        CommonCommand::Sys {
            field: Some(SysField::Configuration),
        } => cli_println(out, state.mode.configuration_state()).await?,
        CommonCommand::Sys {
            field: Some(SysField::Board),
        } => cli_println(out, state.model).await?,
        CommonCommand::Sys {
            field: Some(SysField::Version),
        } => cli_field(out, "version", state.firmware_version).await?,
        CommonCommand::Sys {
            field: Some(SysField::Id),
        } => {
            let device_id = state.identity.device_id();
            cli_println(out, device_id.as_str()).await?;
        }
        CommonCommand::Sys {
            field: Some(SysField::ResetReason),
        } => cli_println(out, state.reset_reason).await?,
        CommonCommand::Sys {
            field: Some(SysField::Temp),
        } => shell.write_temperature(out, None).await?,
        CommonCommand::Sys {
            field: Some(SysField::Uptime),
        } => cli_line(out, format_args!("{}ms", EmbassyInstant::now().as_millis())).await?,
        CommonCommand::Sys {
            field: Some(SysField::Time),
        } => cli_time(out, state.unix_time).await?,
        CommonCommand::Sys {
            field: Some(SysField::Memory),
        } => shell.write_memory(out, None).await?,

        CommonCommand::Ping { iface, addr, count } => {
            let selected = match iface {
                PingIface::Net => Some(state.outer_stack),
                PingIface::Tunnel => state.tunnel_stack,
            };
            match selected {
                Some(stack) => cli_ping(out, iface.name(), stack, addr, count).await?,
                None => cli_println(out, NO_TUNNEL).await?,
            }
        }

        CommonCommand::Tunnel {
            action: None | Some(TunnelAction::Show),
        } => match (state.tunnel_status, state.tunnel_stack) {
            (Some(status), Some(stack)) => write_tunnel_status(out, status, &stack).await?,
            _ => cli_println(out, NO_TUNNEL).await?,
        },
        CommonCommand::Tunnel {
            action: Some(TunnelAction::Key),
        } => match state.tunnel_status {
            Some(status) => {
                let snapshot = status.snapshot();
                let encoded = encode_key(&snapshot.public_key);
                cli_println(out, encoded.as_str()).await?;
            }
            None => cli_println(out, NO_TUNNEL).await?,
        },

        CommonCommand::Config { action: None } => {
            cli_println(out, YMODEM_READY).await?;
            cli_println(
                out,
                "send device configuration TOML with YMODEM-1K/CRC now; Ctrl-X cancels",
            )
            .await?;
            out.flush().await?;
            shell.request_action(SessionAction::ConfigInstall);
            return Err(CliError::Disconnected);
        }
        CommonCommand::Config {
            action: Some(ConfigAction::Clear),
        } => {
            cli_println(out, "clearing persisted device configuration").await?;
            out.flush().await?;
            shell.request_action(SessionAction::ConfigClear);
            return Err(CliError::Disconnected);
        }

        CommonCommand::Fw {
            action: None | Some(FirmwareAction::Show),
        } => {
            FW_TABLE
                .field(out, "version", state.firmware_version)
                .await?;
            FW_TABLE.field(out, "slot", state.firmware.slot).await?;
            FW_TABLE.field(out, "state", state.firmware.state).await?;
        }
        CommonCommand::Fw {
            action: Some(FirmwareAction::Update),
        } => {
            cli_println(out, YMODEM_READY).await?;
            cli_println(out, "send signed MCUboot image now; Ctrl-X cancels").await?;
            out.flush().await?;
            shell.request_action(SessionAction::FirmwareUpdate);
            return Err(CliError::Disconnected);
        }

        CommonCommand::Identify => {
            if state.mode == Mode::Setup {
                cli_line(
                    out,
                    format_args!("identifying: {SETUP_IDENTIFY_SECONDS} seconds"),
                )
                .await?;
                out.flush().await?;
            }
            shell.identify().await;
            if state.mode == Mode::Operational {
                cli_println(out, "ok").await?;
            }
        }

        CommonCommand::Reboot => {
            cli_println(out, "rebooting").await?;
            out.flush().await?;
            shell.request_action(SessionAction::Reboot);
            return Err(CliError::Disconnected);
        }
        CommonCommand::Quit => {
            cli_println(out, "bye").await?;
            out.flush().await?;
            return Err(CliError::Disconnected);
        }
    }

    Ok(())
}
