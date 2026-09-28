use std::{path::PathBuf, process::ExitCode};

const DEFAULT_TUN_NAME: &str = "mt0";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Name of the Linux TUN interface to create.
    #[arg(
        short = 'i',
        long,
        default_value = DEFAULT_TUN_NAME,
        value_name = "NAME",
        value_parser = clap::builder::NonEmptyStringValueParser::new()
    )]
    interface: String,

    /// Path to the microtun device configuration file.
    #[arg(value_name = "CONFIG")]
    config: PathBuf,
}

pub(crate) async fn execute(args: Args) -> ExitCode {
    let _ = (args.interface, args.config);
    eprintln!("error: `microtun tunnel` requires Linux");
    ExitCode::FAILURE
}
