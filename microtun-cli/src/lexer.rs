use heapless::Vec;

use crate::{ParseError, ParseErrorKind};

pub const MAX_TOKENS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token {
    start: u16,
    end: u16,
}

#[derive(Debug)]
pub struct Lexed<'a> {
    bytes: &'a [u8],
    tokens: Vec<Token, MAX_TOKENS>,
}

impl<'a> Lexed<'a> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn arg(&self, index: usize) -> Result<&'a str, ParseError> {
        let token = self
            .tokens
            .get(index)
            .ok_or(ParseError::new(ParseErrorKind::UnexpectedArgument))?;
        core::str::from_utf8(&self.bytes[token.start as usize..token.end as usize])
            .map_err(|_| ParseError::new(ParseErrorKind::InvalidUtf8))
    }
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

pub fn lex(buffer: &mut [u8], len: usize) -> Result<Lexed<'_>, ParseError> {
    if len > buffer.len() || len > u16::MAX as usize {
        return Err(ParseError::new(ParseErrorKind::LineTooLong));
    }

    let mut tokens = Vec::<Token, MAX_TOKENS>::new();
    let mut read = 0usize;
    let mut write = 0usize;

    while read < len {
        while read < len && is_space(buffer[read]) {
            read += 1;
        }
        if read == len {
            break;
        }

        let start = write;
        let mut quote: Option<u8> = None;

        while read < len {
            let b = buffer[read];
            match quote {
                Some(q) if b == q => {
                    quote = None;
                    read += 1;
                }
                Some(_) if b == b'\\' => {
                    read += 1;
                    if read == len {
                        return Err(ParseError::new(ParseErrorKind::TrailingEscape));
                    }
                    buffer[write] = buffer[read];
                    write += 1;
                    read += 1;
                }
                Some(_) => {
                    buffer[write] = b;
                    write += 1;
                    read += 1;
                }
                None if matches!(b, b'\'' | b'"') => {
                    quote = Some(b);
                    read += 1;
                }
                None if b == b'\\' => {
                    read += 1;
                    if read == len {
                        return Err(ParseError::new(ParseErrorKind::TrailingEscape));
                    }
                    buffer[write] = buffer[read];
                    write += 1;
                    read += 1;
                }
                None if is_space(b) => break,
                None => {
                    buffer[write] = b;
                    write += 1;
                    read += 1;
                }
            }
        }

        if quote.is_some() {
            return Err(ParseError::new(ParseErrorKind::UnterminatedQuote));
        }

        tokens
            .push(Token {
                start: start as u16,
                end: write as u16,
            })
            .map_err(|_| ParseError::new(ParseErrorKind::TooManyTokens))?;

        while read < len && is_space(buffer[read]) {
            read += 1;
        }
    }

    Ok(Lexed {
        bytes: &buffer[..write],
        tokens,
    })
}
