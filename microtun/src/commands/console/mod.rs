mod client;
mod keymap;
mod tui;
mod upload;

use std::{
    io::{self, IsTerminal},
    process::ExitCode,
    time::Duration,
};

use self::client::TelnetClient;
use crate::commands::serial_settings::{FlowControl, Parity, SerialSettings, StopBits};

const DEFAULT_TELNET_PORT: u16 = 23;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Device IP address or hostname.
    #[arg(value_name = "TARGET")]
    target: String,

    /// TCP port. Defaults to 23, or 2217 with --serial.
    #[arg(short, long)]
    port: Option<u16>,

    /// Open an RFC 2217 serial console and negotiate COM-PORT-OPTION at startup.
    #[arg(long)]
    serial: bool,

    /// Set the serial baud rate.
    #[arg(long = "baudrate", value_name = "BAUD", requires = "serial")]
    baudrate: Option<u32>,

    /// Set serial data bits.
    #[arg(
        long,
        value_name = "BITS",
        value_parser = clap::value_parser!(u8).range(5..=8),
        requires = "serial"
    )]
    data_bits: Option<u8>,

    /// Set serial parity.
    #[arg(
        long,
        value_enum,
        ignore_case = true,
        value_name = "PARITY",
        requires = "serial"
    )]
    parity: Option<Parity>,

    /// Set serial stop bits.
    #[arg(long, value_enum, value_name = "BITS", requires = "serial")]
    stop_bits: Option<StopBits>,

    /// Set serial flow control.
    #[arg(
        long,
        value_enum,
        ignore_case = true,
        value_name = "MODE",
        requires = "serial"
    )]
    flow_control: Option<FlowControl>,

    /// Telnet connect/read and YMODEM transfer timeout in seconds.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
}

pub(crate) async fn execute(args: Args) -> ExitCode {
    match run_console(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_console(args: Args) -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("microtun console requires an interactive terminal".to_owned());
    }

    let timeout = Duration::from_secs(args.timeout);
    let port = console_port(args.port, args.serial);

    eprintln!("connecting to {} on port {port}", args.target);
    let mut client = TelnetClient::connect(&args.target, port, timeout).await?;
    if args.serial {
        client
            .enter_serial_mode(serial_settings(&args))
            .await
            .map_err(|error| format!("start serial negotiation: {error}"))?;
    }
    tui::run_session(client, &args.target, port, args.serial).await
}

fn serial_settings(args: &Args) -> SerialSettings {
    SerialSettings {
        baud: args.baudrate,
        data_bits: args.data_bits,
        parity: args.parity.map(Parity::protocol_value),
        stop_bits: args.stop_bits.map(StopBits::protocol_value),
        flow: args.flow_control.map(FlowControl::protocol_value),
    }
}

fn console_port(port: Option<u16>, serial: bool) -> u16 {
    port.unwrap_or(if serial {
        microtun_telnet::serial::DEFAULT_PORT
    } else {
        DEFAULT_TELNET_PORT
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use microtun_telnet::serial;

    use super::{Args, console_port, serial_settings};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn telnet_console_defaults_to_telnet_port() {
        let cli = TestCli::try_parse_from(["test", "device.example.net"]).unwrap();
        assert!(!cli.args.serial);
        assert_eq!(console_port(cli.args.port, cli.args.serial), 23);
    }

    #[test]
    fn serial_console_defaults_to_rfc2217_port() {
        let cli = TestCli::try_parse_from(["test", "device.example.net", "--serial"]).unwrap();
        assert!(cli.args.serial);
        assert_eq!(console_port(cli.args.port, cli.args.serial), 2217);
    }

    #[test]
    fn explicit_port_overrides_mode_default() {
        let cli =
            TestCli::try_parse_from(["test", "device.example.net", "--serial", "--port", "9000"])
                .unwrap();
        assert_eq!(console_port(cli.args.port, cli.args.serial), 9000);
    }

    #[test]
    fn accepts_complete_serial_startup_settings() {
        let cli = TestCli::try_parse_from([
            "test",
            "device.example.net",
            "--serial",
            "--baudrate",
            "57600",
            "--data-bits",
            "7",
            "--parity",
            "even",
            "--stop-bits",
            "2",
            "--flow-control",
            "rts-cts",
        ])
        .unwrap();
        let settings = serial_settings(&cli.args);
        assert_eq!(settings.baud, Some(57_600));
        assert_eq!(settings.data_bits, Some(7));
        assert_eq!(settings.parity, Some(serial::parity::EVEN));
        assert_eq!(settings.stop_bits, Some(serial::stop_size::TWO));
        assert_eq!(
            settings.flow,
            Some((
                serial::control::HARDWARE_OUTBOUND,
                serial::control::HARDWARE_INBOUND,
            ))
        );
    }

    #[test]
    fn serial_settings_require_serial_mode() {
        let error = TestCli::try_parse_from(["test", "device.example.net", "--baudrate", "115200"])
            .unwrap_err();
        assert!(error.to_string().contains("--serial"));
    }

    #[test]
    fn rejects_removed_serial_flag_aliases() {
        for args in [
            vec!["test", "device.example.net", "--serial", "-b", "115200"],
            vec!["test", "device.example.net", "--serial", "-7"],
            vec!["test", "device.example.net", "--serial", "-8"],
            vec!["test", "device.example.net", "--serial", "--7bit"],
            vec!["test", "device.example.net", "--serial", "--8bit"],
        ] {
            assert!(TestCli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn rejects_removed_serial_value_aliases() {
        assert!(
            TestCli::try_parse_from(["test", "device.example.net", "--serial", "--parity", "e",])
                .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "device.example.net",
                "--serial",
                "--flow-control",
                "hardware",
            ])
            .is_err()
        );
    }
}
