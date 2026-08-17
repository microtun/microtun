//! Provisioning-command Telnet CLI wire constants.
//!
//! `provision` is a command of the normal line-oriented device console. The full
//! INI payload is transferred with YMODEM-1K/CRC after that command so a
//! multi-kilobyte configuration never has to fit in the CLI line buffer.

/// Standard Telnet port exposed by a device while it is in provisioning mode.
pub const PROVISION_PORT: u16 = 23;
/// Prompt used by the device Telnet CLI in both provisioning and operational mode.
pub const TELNET_PROMPT: &str = "microtun> ";
/// Backward-compatible provisioning name for the shared Telnet prompt.
pub const PROVISION_PROMPT: &str = TELNET_PROMPT;
/// Marker emitted immediately before the CLI hands the socket to YMODEM.
pub const PROVISION_YMODEM_READY: &str = "MICROTUN-PROVISION-YMODEM-1K READY";
/// Marker emitted after the configuration has been validated, persisted, and
/// verified. The device resets immediately after flushing this line.
pub const PROVISION_STORED: &str = "configuration stored; rebooting";
/// Physical identify duration used by the provisioning host workflow.
pub const IDENTIFY_SECONDS: u8 = 5;
