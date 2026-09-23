//! Minimal integration shape for `embassy-net`.
//!
//! In real firmware the socket is created from your Embassy network stack and accepted/listened
//! before being passed to `serve_socket`.

#[cfg(feature = "embassy-net")]
mod demo {
    use core::net::Ipv4Addr;

    use embedded_io_async::Write;
    use microtun_cli::{
        Config, Dispatch, Error, ErrorKind, Parser, Session, Subcommand, ValueEnum, write_fmt,
    };

    pub struct Device {
        pub reboots: u32,
    }

    #[derive(Clone, Copy, Debug, ValueEnum)]
    enum LogLevel {
        Error,
        Warn,
        Info,
        Debug,
        Trace,
    }

    impl Device {
        async fn status<W: Write<Error = ErrorKind> + ?Sized>(
            _this: &mut Self,
            out: &mut W,
            verbose: bool,
        ) -> Result<(), Error> {
            out.write_all(b"status: ok\r\n").await?;
            if verbose {
                out.write_all(b"network: up\r\n").await?;
            }
            Ok(())
        }

        async fn set_ip<W: Write<Error = ErrorKind> + ?Sized>(
            _this: &mut Self,
            out: &mut W,
            address: Ipv4Addr,
            prefix: u8,
        ) -> Result<(), Error> {
            write_fmt::<64, _>(out, format_args!("address: {address}/{prefix}\r\n")).await
        }

        async fn set_log<W: Write<Error = ErrorKind> + ?Sized>(
            _this: &mut Self,
            out: &mut W,
            level: LogLevel,
        ) -> Result<(), Error> {
            write_fmt::<64, _>(out, format_args!("log level: {level:?}\r\n")).await
        }
    }

    #[derive(Subcommand, Dispatch)]
    #[dispatch(context = Device)]
    enum NetCommand {
        /// Assign a static IPv4 address.
        #[command(handler = Device::set_ip)]
        Static {
            /// IPv4 address to assign.
            address: Ipv4Addr,

            /// CIDR prefix length.
            #[arg(short, long, default_value_t = 24)]
            prefix: u8,
        },
    }

    #[derive(Parser, Dispatch)]
    #[command(
        name = "device",
        about = "microtun embedded console",
        version = "0.1.0"
    )]
    #[dispatch(context = Device)]
    enum Command {
        /// Show device status.
        #[command(handler = Device::status)]
        Status {
            /// Include detailed status fields.
            #[arg(short, long)]
            verbose: bool,
        },

        /// Configure networking.
        Net {
            #[command(subcommand)]
            command: NetCommand,
        },

        /// Set the log level.
        #[command(handler = Device::set_log)]
        Log {
            #[arg(value_enum)]
            level: LogLevel,
        },
    }

    pub async fn serve_socket(
        socket: &mut embassy_net::tcp::TcpSocket<'_>,
        device: &mut Device,
    ) -> Result<(), Error> {
        Session::<_, 256, 8, 256>::new(socket, Config::new("device> ").banner("microtun-cli"))
            .serve::<CommandParser, _>(device)
            .await
    }
}

fn main() {}
