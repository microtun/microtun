#[cfg(target_os = "linux")]
mod cuse;
#[cfg(target_os = "linux")]
mod device;

use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;

use crate::commands::serial_settings::{FlowControl, Parity, SerialSettings, StopBits};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Device IP address or hostname.
    #[arg(value_name = "TARGET")]
    target: String,

    /// Local character-device name. The device is created as /dev/NAME.
    #[arg(short = 'n', long, value_name = "NAME", default_value = "ttyMT0")]
    name: String,

    /// Serial TCP port. Defaults to 2217.
    #[arg(short, long, default_value_t = microtun_telnet::serial::DEFAULT_PORT)]
    port: u16,

    /// Set the initial serial baud rate.
    #[arg(long = "baudrate", value_name = "BAUD")]
    baudrate: Option<u32>,

    /// Set initial serial data bits.
    #[arg(
        long,
        value_name = "BITS",
        value_parser = clap::value_parser!(u8).range(5..=8)
    )]
    data_bits: Option<u8>,

    /// Set initial serial parity.
    #[arg(long, value_enum, ignore_case = true, value_name = "PARITY")]
    parity: Option<Parity>,

    /// Set initial serial stop bits.
    #[arg(long, value_enum, value_name = "BITS")]
    stop_bits: Option<StopBits>,

    /// Set initial serial flow control.
    #[arg(long, value_enum, ignore_case = true, value_name = "MODE")]
    flow_control: Option<FlowControl>,

    /// Connect and serial negotiation timeout in seconds.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// Enable debug logging for serial confirmations, modem state, and line state changes.
    #[arg(short, long)]
    verbose: bool,
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

pub(crate) async fn execute(args: Args) -> ExitCode {
    crate::logging::init(if args.verbose {
        "info,microtun=debug"
    } else {
        "info"
    });

    match run_serial(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error);
            ExitCode::FAILURE
        }
    }
}

async fn run_serial(args: Args) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        tracing::info!(
            target = %args.target,
            port = args.port,
            "connecting in serial-device mode"
        );
        let settings = serial_settings(&args);
        return device::run_device(
            &args.target,
            args.port,
            Duration::from_secs(args.timeout),
            &args.name,
            settings,
        )
        .await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        Err("microtun serial requires Linux CUSE support".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use microtun_telnet::serial;

    use super::{Args, serial_settings};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn accepts_complete_serial_startup_settings() {
        let cli = TestCli::try_parse_from([
            "test",
            "device.example.net",
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
    fn rejects_invalid_data_bits() {
        assert!(
            TestCli::try_parse_from(["test", "device.example.net", "--data-bits", "9"]).is_err()
        );
    }

    #[test]
    fn rejects_removed_serial_flag_aliases() {
        for args in [
            vec!["test", "device.example.net", "-b", "115200"],
            vec!["test", "device.example.net", "-7"],
            vec!["test", "device.example.net", "-8"],
            vec!["test", "device.example.net", "--7bit"],
            vec!["test", "device.example.net", "--8bit"],
        ] {
            assert!(TestCli::try_parse_from(args).is_err());
        }
    }
}
