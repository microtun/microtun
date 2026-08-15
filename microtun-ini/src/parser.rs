use crate::{Error, ErrorKind, ROOT_SECTION};

#[derive(Clone, Copy, Debug)]
pub(crate) struct RawLine<'de> {
    pub(crate) text: &'de str,
    pub(crate) start: usize,
    pub(crate) next: usize,
    pub(crate) number: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Lines<'de> {
    input: &'de str,
    offset: usize,
    number: usize,
}

impl<'de> Lines<'de> {
    pub(crate) const fn new(input: &'de str) -> Self {
        Self {
            input,
            offset: 0,
            number: 1,
        }
    }

    pub(crate) fn next(&mut self) -> Option<RawLine<'de>> {
        if self.offset >= self.input.len() {
            return None;
        }

        let start = self.offset;
        let rest = &self.input[start..];
        let (mut end, next) = match rest.as_bytes().iter().position(|byte| *byte == b'\n') {
            Some(relative) => (start + relative, start + relative + 1),
            None => (self.input.len(), self.input.len()),
        };
        if end > start && self.input.as_bytes()[end - 1] == b'\r' {
            end -= 1;
        }

        let line = RawLine {
            text: &self.input[start..end],
            start,
            next,
            number: self.number,
        };
        self.offset = next;
        self.number += 1;
        Some(line)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ParsedLine<'de> {
    Empty,
    Section {
        name: &'de str,
        column: usize,
    },
    Property {
        key: &'de str,
        value: &'de str,
        key_column: usize,
        value_column: usize,
    },
}

pub(crate) fn parse_line<'de>(line: RawLine<'de>) -> Result<ParsedLine<'de>, Error> {
    let mut text = line.text;
    if line.start == 0 {
        text = text.strip_prefix('\u{feff}').unwrap_or(text);
    }
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
        return Ok(ParsedLine::Empty);
    }

    if trimmed.starts_with('[') {
        let column = text.len() - text.trim_start().len() + 1;
        let Some(body) = trimmed
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        else {
            return Err(Error::at(ErrorKind::InvalidSection, line.number, column));
        };
        let name = body.trim();
        if name.is_empty() {
            return Err(Error::at(
                ErrorKind::EmptySectionName,
                line.number,
                column + 1,
            ));
        }
        if name.eq_ignore_ascii_case(ROOT_SECTION) {
            return Err(Error::at(
                ErrorKind::ReservedSectionName,
                line.number,
                column + 1,
            ));
        }
        if name.contains('[') || name.contains(']') {
            return Err(Error::at(ErrorKind::InvalidSection, line.number, column));
        }
        return Ok(ParsedLine::Section { name, column });
    }

    let delimiter = trimmed
        .as_bytes()
        .iter()
        .position(|byte| *byte == b'=' || *byte == b':')
        .ok_or_else(|| {
            Error::at(
                ErrorKind::MissingDelimiter,
                line.number,
                text.len() - text.trim_start().len() + 1,
            )
        })?;
    let key_part = &trimmed[..delimiter];
    let value_part = &trimmed[delimiter + 1..];
    let key = key_part.trim();
    if key.is_empty() {
        let base = text.len() - text.trim_start().len();
        return Err(Error::at(
            ErrorKind::EmptyKey,
            line.number,
            base + delimiter + 1,
        ));
    }
    let value = value_part.trim();
    let base = text.len() - text.trim_start().len();
    let value_leading = value_part.len() - value_part.trim_start().len();
    Ok(ParsedLine::Property {
        key,
        value,
        key_column: base + key_part.len() - key_part.trim_start().len() + 1,
        value_column: base + delimiter + 2 + value_leading,
    })
}

pub(crate) fn validate(input: &str) -> Result<(), Error> {
    let mut lines = Lines::new(input);
    while let Some(line) = lines.next() {
        parse_line(line)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Block<'de> {
    pub(crate) name: &'de str,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) header_start: usize,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

#[derive(Clone, Copy, Debug)]
struct Header<'de> {
    name: &'de str,
    start: usize,
    content_start: usize,
    line: usize,
    column: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Blocks<'de> {
    input: &'de str,
    lines: Lines<'de>,
    pending: Option<Header<'de>>,
    started: bool,
    finished: bool,
}

impl<'de> Blocks<'de> {
    pub(crate) const fn new(input: &'de str) -> Self {
        Self {
            input,
            lines: Lines::new(input),
            pending: None,
            started: false,
            finished: false,
        }
    }

    pub(crate) fn next(&mut self) -> Option<Block<'de>> {
        if self.finished {
            return None;
        }

        if !self.started {
            self.started = true;
            let mut has_global_property = false;
            while let Some(raw) = self.lines.next() {
                match parse_line(raw).expect("document was validated") {
                    ParsedLine::Property { .. } => has_global_property = true,
                    ParsedLine::Section { name, column } => {
                        self.pending = Some(Header {
                            name,
                            start: raw.start,
                            content_start: raw.next,
                            line: raw.number,
                            column,
                        });
                        if has_global_property {
                            return Some(Block {
                                name: ROOT_SECTION,
                                start: 0,
                                end: raw.start,
                                header_start: 0,
                                line: 1,
                                column: 1,
                            });
                        }
                        break;
                    }
                    ParsedLine::Empty => {}
                }
            }

            if self.pending.is_none() {
                self.finished = true;
                return has_global_property.then_some(Block {
                    name: ROOT_SECTION,
                    start: 0,
                    end: self.input.len(),
                    header_start: 0,
                    line: 1,
                    column: 1,
                });
            }
        }

        let header = self.pending.take()?;
        while let Some(raw) = self.lines.next() {
            if let ParsedLine::Section { name, column } =
                parse_line(raw).expect("document was validated")
            {
                self.pending = Some(Header {
                    name,
                    start: raw.start,
                    content_start: raw.next,
                    line: raw.number,
                    column,
                });
                return Some(Block {
                    name: header.name,
                    start: header.content_start,
                    end: raw.start,
                    header_start: header.start,
                    line: header.line,
                    column: header.column,
                });
            }
        }

        self.finished = true;
        Some(Block {
            name: header.name,
            start: header.content_start,
            end: self.input.len(),
            header_start: header.start,
            line: header.line,
            column: header.column,
        })
    }
}

pub(crate) fn seen_block_before(input: &str, candidate: Block<'_>) -> bool {
    let mut blocks = Blocks::new(input);
    while let Some(block) = blocks.next() {
        if block.header_start >= candidate.header_start {
            return false;
        }
        if block.name.eq_ignore_ascii_case(candidate.name) {
            return true;
        }
    }
    false
}

pub(crate) fn matching_block_count(input: &str, name: &str) -> usize {
    let mut count = 0;
    let mut blocks = Blocks::new(input);
    while let Some(block) = blocks.next() {
        if block.name.eq_ignore_ascii_case(name) {
            count += 1;
        }
    }
    count
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Property<'de> {
    pub(crate) key: &'de str,
    pub(crate) value: &'de str,
    pub(crate) line: usize,
    pub(crate) key_column: usize,
    pub(crate) value_column: usize,
    pub(crate) offset: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Properties<'de> {
    input: &'de str,
    block: Block<'de>,
    lines: Lines<'de>,
}

impl<'de> Properties<'de> {
    pub(crate) fn new(input: &'de str, block: Block<'de>) -> Self {
        Self {
            input,
            block,
            lines: Lines::new(&input[block.start..block.end]),
        }
    }

    pub(crate) fn next(&mut self) -> Option<Property<'de>> {
        while let Some(raw) = self.lines.next() {
            if let ParsedLine::Property {
                key,
                value,
                key_column,
                value_column,
            } = parse_line(raw).expect("document was validated")
            {
                let absolute_offset = self.block.start + raw.start;
                let absolute_line = line_number_at(self.input, absolute_offset);
                return Some(Property {
                    key,
                    value,
                    line: absolute_line,
                    key_column,
                    value_column,
                    offset: absolute_offset,
                });
            }
        }
        None
    }
}

fn line_number_at(input: &str, offset: usize) -> usize {
    input.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

pub(crate) fn seen_property_before(input: &str, block: Block<'_>, candidate: Property<'_>) -> bool {
    let mut properties = Properties::new(input, block);
    while let Some(property) = properties.next() {
        if property.offset >= candidate.offset {
            return false;
        }
        if property.key.eq_ignore_ascii_case(candidate.key) {
            return true;
        }
    }
    false
}

pub(crate) fn matching_property_count(input: &str, block: Block<'_>, key: &str) -> usize {
    let mut count = 0;
    let mut properties = Properties::new(input, block);
    while let Some(property) = properties.next() {
        if property.key.eq_ignore_ascii_case(key) {
            count += 1;
        }
    }
    count
}
