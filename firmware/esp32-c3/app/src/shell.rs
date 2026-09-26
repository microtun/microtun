//! Telnet shell and ESP32-C3-specific diagnostics.
//!
//! Command/session flow and setup-vs-operational state live in `firmware/common`; this module
//! contributes only ESP hardware access and the board-specific `net wifi` view.

use embassy_net::Stack;
use embassy_time::Instant as EmbassyInstant;
use embedded_io_async::Write as AsyncWrite;
use esp_hal::{system::software_reset, tsens::TemperatureSensor};
use log::info;
use microtun_cli::{Dispatch, Error as CliError, ErrorKind, Parser, ValueEnum};
use microtun_embassy::TunnelStatus;
use microtun_firmware_common::{
    cli::{
        Table, line as cli_line, write_ip_status as cli_write_ip_status,
        write_link_status as cli_write_link_status, write_mac_status as cli_write_mac_status,
        write_net_base as cli_write_net_base,
    },
    configuration::{DeviceIdentity, RECORD_SIZE},
    firmware::FirmwareStatus,
    net::{ntp_unix_time, query_ntp_time},
    shell::{CommonCommand, ShellContext, ShellState, dispatch_common},
    telnet::{SessionAction, serve as serve_telnet},
};

use crate::{
    ESP_APP_DESC,
    board::{DEVICE_MODEL, IdentifyLedPin},
    network::wifi_link_snapshot,
    storage::Storage,
};

const TELNET_BANNER: &str = "microtun ESP32-C3\r\ntype 'help' for commands";
const SETUP_TELNET_BANNER: &str = "microtun ESP32-C3 setup mode\r\ntype 'help' for commands";

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

#[derive(Clone, Copy)]
pub(crate) struct WallClock {
    unix_secs: u64,
    unix_nanos: u32,
    sample: EmbassyInstant,
}

impl WallClock {
    pub(crate) fn new(unix_secs: u64, unix_nanos: u32) -> Self {
        Self {
            unix_secs,
            unix_nanos,
            sample: EmbassyInstant::now(),
        }
    }

    pub(crate) fn now(self) -> (u64, u32) {
        let elapsed_us = EmbassyInstant::now()
            .as_micros()
            .saturating_sub(self.sample.as_micros());
        let base_us = u64::from(self.unix_nanos / 1_000);
        let total_us = base_us.saturating_add(elapsed_us);
        (
            self.unix_secs.saturating_add(total_us / 1_000_000),
            ((total_us % 1_000_000) * 1_000) as u32,
        )
    }
}

pub(crate) async fn sync_time_from_ntp(stack: Stack<'static>, host: &str, port: u16) -> (u64, u32) {
    let result = query_ntp_time(stack, host, port).await;
    let (unix_secs, unix_nanos) = ntp_unix_time(&result);
    info!(
        "time synchronized from {}: unix={} stratum={} rtt={}us",
        host,
        unix_secs,
        result.stratum(),
        result.roundtrip()
    );
    (unix_secs, unix_nanos)
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetField {
    /// Show whether the network link is up.
    Link,
    /// Show the configured IP address and gateway.
    Ip,
    /// Show the network MAC address.
    Mac,
    /// Show Wi-Fi association and signal details.
    Wifi,
}

#[derive(Debug, Parser)]
#[command(name = "microtun", about = "microtun ESP32-C3 shell")]
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

const NET_TABLE: Table = Table::new(&["link", "ip", "mac", "wifi"]);
const WIFI_TABLE: Table = Table::new(&["ssid", "bssid", "channel", "rssi", "reconnects"]);

/// One shell type serves both setup and operational mode.
pub(crate) struct Shell {
    state: ShellState,
    pending_action: Option<SessionAction>,
    wall_clock: Option<WallClock>,
    mac: [u8; 6],
    wifi_ssid: heapless::String<32>,
    temperature_sensor: TemperatureSensor<'static>,
    identify_led: IdentifyLedPin,
}

impl Shell {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn setup(
        identity: DeviceIdentity,
        reset_reason: &'static str,
        stack: Stack<'static>,
        firmware_status: FirmwareStatus,
        mac: [u8; 6],
        wifi_ssid: heapless::String<32>,
        temperature_sensor: TemperatureSensor<'static>,
        identify_led: IdentifyLedPin,
    ) -> Self {
        Self {
            state: ShellState::setup(
                DEVICE_MODEL,
                ESP_APP_DESC.version(),
                identity,
                reset_reason,
                stack,
                firmware_status,
            ),
            pending_action: None,
            wall_clock: None,
            mac,
            wifi_ssid,
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
        wall_clock: Option<WallClock>,
        mac: [u8; 6],
        wifi_ssid: heapless::String<32>,
        temperature_sensor: TemperatureSensor<'static>,
        identify_led: IdentifyLedPin,
    ) -> Self {
        Self {
            state: ShellState::operational(
                DEVICE_MODEL,
                ESP_APP_DESC.version(),
                identity,
                reset_reason,
                outer_stack,
                inner_stack,
                tunnel_status,
                firmware_status,
            ),
            pending_action: None,
            wall_clock,
            mac,
            wifi_ssid,
            temperature_sensor,
            identify_led,
        }
    }
}

impl ShellContext for Shell {
    fn state(&self) -> ShellState {
        self.state
            .with_unix_time(self.wall_clock.map(WallClock::now))
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
        // The attached board only has a hard-wired power LED, so there is no
        // GPIO-backed identify action on this example target.
        let _ = &mut self.identify_led;
    }

    fn reset(&self) -> ! {
        software_reset()
    }

    fn pending_action(&mut self) -> &mut Option<SessionAction> {
        &mut self.pending_action
    }
}

async fn write_temperature<W>(
    out: &mut W,
    sensor: &mut TemperatureSensor<'static>,
    table: Option<Table>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = ErrorKind> + ?Sized,
{
    let celsius = sensor.get_temperature().to_celsius();
    match table {
        Some(table) => {
            table
                .field_fmt(out, "temp", format_args!("{celsius:.1} C"))
                .await
        }
        None => cli_line(out, format_args!("{celsius:.1} C")).await,
    }
}

async fn write_memory<W>(out: &mut W, table: Option<Table>) -> Result<(), CliError>
where
    W: AsyncWrite<Error = ErrorKind> + ?Sized,
{
    let memory = esp_alloc::HEAP.stats();
    let free = memory.size.saturating_sub(memory.current_usage);
    let percent = memory
        .current_usage
        .saturating_mul(100)
        .checked_div(memory.size)
        .unwrap_or(0);
    match table {
        Some(table) => {
            table
                .field_fmt(
                    out,
                    "memory",
                    format_args!(
                        "{}B/{}B ({percent}%) free={free}B",
                        memory.current_usage, memory.size
                    ),
                )
                .await
        }
        None => {
            cli_line(
                out,
                format_args!(
                    "{}B/{}B ({percent}%) free={free}B",
                    memory.current_usage, memory.size
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
            let wifi = wifi_link_snapshot();
            let ssid = shell.wifi_ssid.as_str();
            if wifi.associated {
                match wifi.rssi_dbm {
                    Some(rssi_dbm) => {
                        NET_TABLE
                            .field_fmt(
                                out,
                                "wifi",
                                format_args!(
                                    "{} ch={} rssi={} dBm reconnects={}",
                                    ssid, wifi.channel, rssi_dbm, wifi.reconnects
                                ),
                            )
                            .await?;
                    }
                    None => {
                        NET_TABLE
                            .field_fmt(
                                out,
                                "wifi",
                                format_args!(
                                    "{} ch={} rssi=n/a reconnects={}",
                                    ssid, wifi.channel, wifi.reconnects
                                ),
                            )
                            .await?;
                    }
                }
            } else {
                NET_TABLE
                    .field_fmt(
                        out,
                        "wifi",
                        format_args!("{} disconnected reconnects={}", ssid, wifi.reconnects),
                    )
                    .await?;
            }
        }
        Some(NetField::Link) => cli_write_link_status(out, stack).await?,
        Some(NetField::Ip) => cli_write_ip_status(out, stack).await?,
        Some(NetField::Mac) => cli_write_mac_status(out, mac).await?,
        Some(NetField::Wifi) => {
            let status = wifi_link_snapshot();
            WIFI_TABLE
                .field(out, "ssid", shell.wifi_ssid.as_str())
                .await?;
            if status.associated {
                WIFI_TABLE
                    .field_fmt(
                        out,
                        "bssid",
                        format_args!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            status.bssid[0],
                            status.bssid[1],
                            status.bssid[2],
                            status.bssid[3],
                            status.bssid[4],
                            status.bssid[5]
                        ),
                    )
                    .await?;
                WIFI_TABLE.field(out, "channel", &status.channel).await?;
                match status.rssi_dbm {
                    Some(rssi_dbm) => {
                        WIFI_TABLE
                            .field_fmt(out, "rssi", format_args!("{rssi_dbm} dBm"))
                            .await?;
                    }
                    None => WIFI_TABLE.field(out, "rssi", "n/a").await?,
                }
            } else {
                WIFI_TABLE.field(out, "bssid", "n/a").await?;
                WIFI_TABLE.field(out, "channel", "n/a").await?;
                WIFI_TABLE.field(out, "rssi", "n/a").await?;
            }
            WIFI_TABLE
                .field(out, "reconnects", &status.reconnects)
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
