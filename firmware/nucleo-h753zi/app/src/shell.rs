//! Telnet shell and Nucleo-specific diagnostics.
//!
//! Command/session flow and setup-vs-operational state live in `firmware/common`; this module
//! contributes only STM32 hardware access, RTC handling, and the board-specific Ethernet PHY view.

use chrono::Datelike;
use defmt::{info, warn};
use embassy_net::Stack;
use embassy_stm32::rtc::{DateTime as RtcDateTime, Rtc, RtcTimeProvider};
use embassy_time::Timer;
use embedded_io_async::Write as AsyncWrite;
use microtun_cli::{Dispatch, Error as CliError, ErrorKind, Parser, ValueEnum};
use microtun_embassy::TunnelStatus;
use microtun_firmware_common::{
    board::{identify_operational_led, identify_setup_led},
    cli::{
        Table, line as cli_line, println as cli_println, write_ip_status as cli_write_ip_status,
        write_link_status as cli_write_link_status, write_mac_status as cli_write_mac_status,
        write_net_base as cli_write_net_base,
    },
    configuration::{DeviceIdentity, RECORD_SIZE},
    firmware::FirmwareStatus,
    net::{ntp_unix_time, query_ntp_time},
    shell::{CommonCommand, Mode, ShellContext, ShellState, dispatch_common},
    telnet::{SessionAction, serve as serve_telnet},
};

use crate::{
    DEVICE_MODEL, FIRMWARE_VERSION, IdentifyLedPin, reset, stm32_phy::phy_link_snapshot,
    storage::Storage, temp_sensor::TemperatureSensor,
};

const TELNET_BANNER: &str = "microtun NUCLEO-H753ZI\r\ntype 'help' for commands";
const SETUP_TELNET_BANNER: &str = "microtun NUCLEO-H753ZI setup mode\r\ntype 'help' for commands";

#[embassy_executor::task]
pub(crate) async fn telnet_task(
    mut shell: Shell,
    storage: &'static Storage,
    configuration_scratch: &'static mut [u8; RECORD_SIZE],
) -> ! {
    serve_telnet::<CommandParser, _, _>(&mut shell, storage, configuration_scratch, TELNET_BANNER)
        .await
}

pub(crate) async fn setup_mode(
    storage: &Storage,
    mut shell: Shell,
    configuration_scratch: &mut [u8; RECORD_SIZE],
) -> ! {
    serve_telnet::<CommandParser, _, _>(
        &mut shell,
        storage,
        configuration_scratch,
        SETUP_TELNET_BANNER,
    )
    .await
}

pub(crate) async fn sync_rtc_from_ntp(
    stack: Stack<'static>,
    rtc: &mut Rtc,
    rtc_time: &RtcTimeProvider,
    host: &str,
    port: u16,
) -> (u64, u32) {
    loop {
        let result = query_ntp_time(stack, host, port).await;
        let (unix_secs, unix_nanos) = ntp_unix_time(&result);
        let Some(datetime) = unix_to_rtc_datetime(unix_secs, unix_nanos) else {
            warn!("SNTP timestamp is outside the STM32 RTC year range");
            Timer::after_secs(2).await;
            continue;
        };

        if let Err(error) = rtc.set_datetime(datetime) {
            warn!("failed to set STM32 RTC from SNTP: {:?}", error);
            Timer::after_secs(2).await;
            continue;
        }

        let (rtc_secs, rtc_nanos) = rtc_unix_time(rtc_time).expect("RTC readable after SNTP sync");
        info!(
            "RTC synchronized from {}: unix={} stratum={} rtt={}us",
            host,
            rtc_secs,
            result.stratum(),
            result.roundtrip()
        );
        return (rtc_secs, rtc_nanos);
    }
}

pub(crate) fn rtc_unix_time(rtc_time: &RtcTimeProvider) -> Option<(u64, u32)> {
    let datetime: chrono::NaiveDateTime = rtc_time.now().ok()?.into();
    let datetime = datetime.and_utc();

    Some((
        u64::try_from(datetime.timestamp()).ok()?,
        datetime.timestamp_subsec_nanos(),
    ))
}

fn unix_to_rtc_datetime(unix_secs: u64, unix_nanos: u32) -> Option<RtcDateTime> {
    let datetime = chrono::DateTime::from_timestamp(i64::try_from(unix_secs).ok()?, unix_nanos)?;

    // STM32's calendar RTC stores a two-digit year relative to 2000.
    if !(2000..=2099).contains(&datetime.year()) {
        return None;
    }

    Some(datetime.naive_utc().into())
}

#[derive(Clone, Copy)]
struct MemoryUsage {
    total: usize,
    static_used: usize,
    stack_used: usize,
    free_now: usize,
}

fn memory_usage() -> MemoryUsage {
    // Report the linker RAM arena selected by embassy-stm32's generated memory.x.
    unsafe extern "C" {
        static _ram_start: u8;
        static _ram_end: u8;
        static _stack_start: u8;
    }

    let ram_start = core::ptr::addr_of!(_ram_start) as usize;
    let ram_end = core::ptr::addr_of!(_ram_end) as usize;
    let stack_start = core::ptr::addr_of!(_stack_start) as usize;
    let static_end = cortex_m_rt::heap_start() as usize;
    let stack_pointer = cortex_m::register::msp::read() as usize;

    MemoryUsage {
        total: ram_end.saturating_sub(ram_start),
        static_used: static_end.saturating_sub(ram_start),
        stack_used: stack_start.saturating_sub(stack_pointer),
        free_now: stack_pointer.saturating_sub(static_end),
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetField {
    /// Show whether the Ethernet link is up.
    Link,
    /// Show the configured IP address and gateway.
    Ip,
    /// Show the Ethernet MAC address.
    Mac,
    /// Show Ethernet PHY status.
    Phy,
}

#[derive(Debug, Parser)]
#[command(name = "microtun", about = "microtun NUCLEO-H753ZI shell")]
enum Command {
    /// `sys`, `ping`, `tunnel`, `config`, `fw`, `identify`, `reboot`, `quit`.
    #[command(flatten)]
    Common(CommonCommand),

    /// Show network status.
    Net {
        #[arg(value_enum, value_name = "FIELD")]
        field: Option<NetField>,
    },
}

const NET_TABLE: Table = Table::new(&["link", "ip", "mac", "phy"]);
const PHY_TABLE: Table = Table::new(&["speed", "duplex", "autoneg"]);

/// One shell type serves both setup and operational mode.
pub(crate) struct Shell {
    state: ShellState,
    pending_action: Option<SessionAction>,
    rtc_time: Option<RtcTimeProvider>,
    mac: [u8; 6],
    temperature_sensor: TemperatureSensor,
    identify_led: IdentifyLedPin,
}

impl Shell {
    pub(crate) fn setup(
        identity: DeviceIdentity,
        reset_reason: &'static str,
        stack: Stack<'static>,
        firmware_status: FirmwareStatus,
        mac: [u8; 6],
        temperature_sensor: TemperatureSensor,
        identify_led: IdentifyLedPin,
    ) -> Self {
        Self {
            state: ShellState::setup(
                DEVICE_MODEL,
                FIRMWARE_VERSION,
                identity,
                reset_reason,
                stack,
                firmware_status,
            ),
            pending_action: None,
            rtc_time: None,
            mac,
            temperature_sensor,
            identify_led,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn operational(
        identity: DeviceIdentity,
        reset_reason: &'static str,
        outer_stack: Stack<'static>,
        inner_stack: Stack<'static>,
        tunnel_status: TunnelStatus<'static>,
        firmware_status: FirmwareStatus,
        rtc_time: RtcTimeProvider,
        mac: [u8; 6],
        temperature_sensor: TemperatureSensor,
        identify_led: IdentifyLedPin,
    ) -> Self {
        Self {
            state: ShellState::operational(
                DEVICE_MODEL,
                FIRMWARE_VERSION,
                identity,
                reset_reason,
                outer_stack,
                inner_stack,
                tunnel_status,
                firmware_status,
            ),
            pending_action: None,
            rtc_time: Some(rtc_time),
            mac,
            temperature_sensor,
            identify_led,
        }
    }
}

impl ShellContext for Shell {
    fn state(&self) -> ShellState {
        self.state
            .with_unix_time(self.rtc_time.as_ref().and_then(rtc_unix_time))
    }

    async fn write_temperature<W>(
        &mut self,
        out: &mut W,
        table: Option<Table>,
    ) -> Result<(), CliError>
    where
        W: AsyncWrite<Error = ErrorKind> + ?Sized,
    {
        write_temperature(out, &mut self.temperature_sensor, table).await
    }

    async fn write_memory<W>(&mut self, out: &mut W, table: Option<Table>) -> Result<(), CliError>
    where
        W: AsyncWrite<Error = ErrorKind> + ?Sized,
    {
        write_memory(out, table).await
    }

    async fn identify(&mut self) {
        if self.state.mode == Mode::Setup {
            identify_setup_led(&mut self.identify_led).await;
        } else {
            identify_operational_led(&mut self.identify_led).await;
        }
    }

    fn reset(&self) -> ! {
        reset()
    }

    fn pending_action(&mut self) -> &mut Option<SessionAction> {
        &mut self.pending_action
    }
}

async fn write_temperature<W>(
    out: &mut W,
    sensor: &mut TemperatureSensor,
    table: Option<Table>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = ErrorKind> + ?Sized,
{
    let Some(millicelsius) = sensor.read_millicelsius().map(i64::from) else {
        return match table {
            Some(table) => table.field(out, "temp", "unavailable").await,
            None => cli_println(out, "unavailable").await,
        };
    };
    let sign = if millicelsius < 0 { "-" } else { "" };
    let magnitude = millicelsius.abs();
    let whole = magnitude / 1000;
    let tenths = (magnitude % 1000) / 100;
    match table {
        Some(table) => {
            table
                .field_fmt(out, "temp", format_args!("{sign}{whole}.{tenths} C"))
                .await
        }
        None => cli_line(out, format_args!("{sign}{whole}.{tenths} C")).await,
    }
}

async fn write_memory<W>(out: &mut W, table: Option<Table>) -> Result<(), CliError>
where
    W: AsyncWrite<Error = ErrorKind> + ?Sized,
{
    let memory = memory_usage();
    let used = memory.static_used.saturating_add(memory.stack_used);
    let percent = used
        .saturating_mul(100)
        .checked_div(memory.total)
        .unwrap_or(0);
    match table {
        Some(table) => {
            table
                .field_fmt(
                    out,
                    "memory",
                    format_args!(
                        "{used}B/{}B ({percent}%) free={}B",
                        memory.total, memory.free_now
                    ),
                )
                .await
        }
        None => {
            cli_line(
                out,
                format_args!(
                    "{used}B/{}B ({percent}%) static={}B stack={}B free={}B",
                    memory.total, memory.static_used, memory.stack_used, memory.free_now
                ),
            )
            .await
        }
    }
}

async fn dispatch_net<W>(
    shell: &mut Shell,
    field: Option<NetField>,
    out: &mut W,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = ErrorKind> + ?Sized,
{
    let stack = shell.state().outer_stack;
    let mac = shell.mac;
    match field {
        None => {
            cli_write_net_base(out, NET_TABLE, stack, mac).await?;
            let phy = phy_link_snapshot();
            match (phy.speed_name(), phy.duplex_name()) {
                (Some(speed), Some(duplex)) => {
                    NET_TABLE
                        .field_fmt(
                            out,
                            "phy",
                            format_args!("{} {} autoneg={}", speed, duplex, phy.autoneg_name()),
                        )
                        .await?;
                }
                _ => {
                    NET_TABLE
                        .field_fmt(
                            out,
                            "phy",
                            format_args!("n/a autoneg={}", phy.autoneg_name()),
                        )
                        .await?;
                }
            }
        }
        Some(NetField::Link) => cli_write_link_status(out, stack).await?,
        Some(NetField::Ip) => cli_write_ip_status(out, stack).await?,
        Some(NetField::Mac) => cli_write_mac_status(out, mac).await?,
        Some(NetField::Phy) => {
            let status = phy_link_snapshot();
            match status.speed_name() {
                Some(speed) => PHY_TABLE.field(out, "speed", speed).await?,
                None => PHY_TABLE.field(out, "speed", "n/a").await?,
            }
            match status.duplex_name() {
                Some(duplex) => PHY_TABLE.field(out, "duplex", duplex).await?,
                None => PHY_TABLE.field(out, "duplex", "n/a").await?,
            }
            PHY_TABLE
                .field(out, "autoneg", status.autoneg_name())
                .await?;
        }
    }
    Ok(())
}

impl Dispatch<Shell> for Command {
    async fn dispatch<W: AsyncWrite<Error = ErrorKind> + ?Sized>(
        self,
        shell: &mut Shell,
        out: &mut W,
    ) -> Result<(), CliError> {
        match self {
            Command::Common(command) => dispatch_common(shell, command, out).await,
            Command::Net { field } => dispatch_net(shell, field, out).await,
        }
    }
}
