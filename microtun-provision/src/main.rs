use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode},
};

use clap::{Parser, ValueEnum};
use microtun_provision::{RECORD_SIZE, decode_json, decode_record, encode_record};

#[derive(Parser)]
#[command(
    name = "microtun-provision",
    version,
    about = "Validate configuration and flash microtun provisioning records"
)]
struct Cli {
    config: PathBuf,
    #[arg(long, value_enum)]
    target: Target,
    /// Address of the provisioning record in the target flash layout.
    #[arg(long, value_parser = parse_u32)]
    address: u32,
    /// Chip name passed to probe-rs for STM32 targets.
    #[arg(long)]
    chip: Option<String>,
    /// espflash executable used for ESP32 targets.
    #[arg(long, default_value = "espflash")]
    espflash: PathBuf,
    /// Serial port passed to espflash.
    #[arg(long)]
    port: Option<String>,
    /// probe-rs executable used for STM32 targets.
    #[arg(long, default_value = "probe-rs")]
    probe_rs: PathBuf,
    /// Debug probe selector passed to probe-rs, for example 0483:374e.
    #[arg(long)]
    probe: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Target {
    #[value(name = "esp32")]
    Esp32,
    #[value(name = "stm32")]
    Stm32,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let json = read_config(&cli.config)?;
    let record = make_record(&json)?;

    match cli.target {
        Target::Esp32 => {
            if cli.chip.is_some() {
                return Err("--chip is only valid with --target stm32".to_owned());
            }
            flash_esp32(&record, &cli.espflash, cli.port.as_deref(), cli.address)
        }
        Target::Stm32 => {
            let chip = cli.chip.as_deref().ok_or_else(|| {
                "--chip is required with --target stm32 (for example STM32H753ZITx)".to_owned()
            })?;
            flash_stm32(
                &record,
                &cli.probe_rs,
                cli.probe.as_deref(),
                chip,
                cli.address,
            )
        }
    }
}

fn read_config(path: &Path) -> Result<Vec<u8>, String> {
    let json = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    decode_json(&json).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(json)
}

fn make_record(json: &[u8]) -> Result<Vec<u8>, String> {
    let mut record = vec![0xff; RECORD_SIZE];
    encode_record(json, &mut record).map_err(|error| error.to_string())?;
    Ok(record)
}

fn flash_esp32(
    record: &[u8],
    espflash: &Path,
    port: Option<&str>,
    address: u32,
) -> Result<(), String> {
    let record_path = temp_path("esp32-record.bin");
    let verify_path = temp_path("esp32-verify.bin");
    let result = (|| {
        fs::write(&record_path, record).map_err(|error| {
            format!("write temporary record {}: {error}", record_path.display())
        })?;

        let mut write = ProcessCommand::new(espflash);
        write.arg("write-bin");
        if let Some(port) = port {
            write.args(["--port", port]);
        }
        write.arg(format!("0x{address:08x}"));
        write.arg(&record_path);
        run_command(write, "write ESP32 provisioning record")?;

        let mut verify = ProcessCommand::new(espflash);
        verify.arg("read-flash");
        if let Some(port) = port {
            verify.args(["--port", port]);
        }
        verify.arg(format!("0x{address:08x}"));
        verify.arg(RECORD_SIZE.to_string());
        verify.arg(&verify_path);
        run_command(verify, "read back ESP32 provisioning record")?;

        let readback = fs::read(&verify_path).map_err(|error| {
            format!("read verification image {}: {error}", verify_path.display())
        })?;
        if readback != record {
            return Err("ESP32 provisioning readback did not match the written record".to_owned());
        }
        decode_record(&readback)
            .map_err(|error| format!("written ESP32 record failed validation: {error}"))?;

        println!("wrote and verified provisioning record at 0x{address:08x}");
        Ok(())
    })();

    let _ = fs::remove_file(&record_path);
    let _ = fs::remove_file(&verify_path);
    result
}

fn flash_stm32(
    record: &[u8],
    probe_rs: &Path,
    probe: Option<&str>,
    chip: &str,
    address: u32,
) -> Result<(), String> {
    let record_path = temp_path("stm32-record.bin");
    let result = (|| {
        fs::write(&record_path, record).map_err(|error| {
            format!("write temporary record {}: {error}", record_path.display())
        })?;

        let mut download = ProcessCommand::new(probe_rs);
        download.args(["download", "--chip", chip]);
        if let Some(probe) = probe {
            download.args(["--probe", probe]);
        }
        download.arg("--binary-format=bin");
        download.arg(format!("--base-address=0x{address:08x}"));
        download.arg("--verify");
        download.arg(&record_path);
        run_command(download, "write and verify STM32 provisioning record")?;

        println!("wrote and verified provisioning record at 0x{address:08x}");
        Ok(())
    })();

    let _ = fs::remove_file(&record_path);
    result
}

fn run_command(mut command: ProcessCommand, action: &str) -> Result<(), String> {
    let display = format!("{command:?}");
    let status = command
        .status()
        .map_err(|error| format!("failed to {action} with {display}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "failed to {action}: {display} exited with {status}"
        ));
    }
    Ok(())
}

fn temp_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "microtun-provision-{}-{suffix}",
        std::process::id()
    ))
}

fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|error| error.to_string())
    } else {
        value.parse::<u32>().map_err(|error| error.to_string())
    }
}
