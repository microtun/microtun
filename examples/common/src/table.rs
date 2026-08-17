//! Formatting for aligned CLI key/value tables.

use core::fmt::{self, Display};

use embedded_io_async::Write as AsyncWrite;
use microtun_telnet_cli::{Error as CliError, IoError, write_fmt};

const TABLE_TAB_WIDTH: usize = 4;

const fn next_tab_stop(width: usize) -> usize {
    let remainder = width % TABLE_TAB_WIDTH;
    let advance = if remainder == 0 {
        TABLE_TAB_WIDTH
    } else {
        TABLE_TAB_WIDTH - remainder
    };
    width.saturating_add(advance)
}

/// Zero-allocation formatter for aligned CLI key/value tables.
///
/// Declare the labels that belong to a table once. The formatter snaps the
/// value column to the next virtual tab stop after the longest label. It emits
/// spaces rather than literal tab characters so alignment is independent of a
/// Telnet client's tab width. Rows with an undeclared longer label snap to their
/// own next tab stop, so a new field can never run into its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Table {
    value_column: usize,
}

impl Table {
    pub const fn new(labels: &[&str]) -> Self {
        let mut longest_label = 0;
        let mut index = 0;
        while index < labels.len() {
            let candidate = labels[index].len();
            if candidate > longest_label {
                longest_label = candidate;
            }
            index += 1;
        }
        Self {
            value_column: next_tab_stop(longest_label),
        }
    }

    pub const fn value_column(self) -> usize {
        self.value_column
    }

    fn row_width(self, name: &str) -> usize {
        self.value_column.max(next_tab_stop(name.len()))
    }

    pub async fn field<W, D>(self, out: &mut W, name: &str, value: &D) -> Result<(), CliError>
    where
        W: AsyncWrite<Error = IoError> + ?Sized,
        D: Display + ?Sized,
    {
        let width = self.row_width(name);
        write_fmt::<256, _>(out, format_args!("{name:<width$}{value}", width = width)).await?;
        out.write_all(b"\r\n").await?;
        Ok(())
    }

    pub async fn field_fmt<W>(
        self,
        out: &mut W,
        name: &str,
        value: fmt::Arguments<'_>,
    ) -> Result<(), CliError>
    where
        W: AsyncWrite<Error = IoError> + ?Sized,
    {
        let width = self.row_width(name);
        write_fmt::<256, _>(out, format_args!("{name:<width$}", width = width)).await?;
        write_fmt::<256, _>(out, value).await?;
        out.write_all(b"\r\n").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{TABLE_TAB_WIDTH, Table, next_tab_stop};

    #[test]
    fn next_tab_stop_advances_to_a_four_column_boundary() {
        assert_eq!(next_tab_stop(1), TABLE_TAB_WIDTH);
        assert_eq!(next_tab_stop(3), TABLE_TAB_WIDTH);
        assert_eq!(next_tab_stop(4), TABLE_TAB_WIDTH * 2);
        assert_eq!(next_tab_stop(7), TABLE_TAB_WIDTH * 2);
    }

    #[test]
    fn compact_table_uses_a_narrow_value_column() {
        let table = Table::new(&["ip", "mac"]);
        assert_eq!(table.value_column(), 4);
    }

    #[test]
    fn table_snaps_after_its_longest_declared_label() {
        let table = Table::new(&["speed", "duplex", "autoneg"]);
        assert_eq!(table.value_column(), 8);

        let sys = Table::new(&["board", "reset-reason"]);
        assert_eq!(sys.value_column(), 16);
    }

    #[test]
    fn undeclared_long_label_uses_its_own_next_tab_stop() {
        let label = "abcdefghijklmn";
        let table = Table::new(&["short"]);
        assert_eq!(table.row_width(label), 16);
    }
}
