use core::str::FromStr;

use serde::de::{
    self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
    value::BorrowedStrDeserializer,
};

use crate::{
    Error, ErrorKind,
    parser::{
        Block, Blocks, Properties, Property, matching_block_count, matching_property_count,
        seen_block_before, seen_property_before,
    },
};

fn canonical_field_name<'de>(name: &'de str, fields: &'static [&'static str]) -> &'de str {
    for &field in fields {
        if field.eq_ignore_ascii_case(name) {
            return field;
        }
    }
    name
}

/// A Serde deserializer over a borrowed INI document.
pub struct Deserializer<'de> {
    pub(crate) input: &'de str,
}

impl<'de> Deserializer<'de> {
    /// Creates a deserializer. Prefer [`crate::from_str`] unless manual Serde
    /// driving is needed.
    pub fn new(input: &'de str) -> Result<Self, Error> {
        crate::parser::validate(input)?;
        Ok(Self { input })
    }
}

impl<'de> de::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(DocumentAccess {
            input: self.input,
            blocks: Blocks::new(self.input),
            pending: None,
            fields: None,
        })
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(DocumentAccess {
            input: self.input,
            blocks: Blocks::new(self.input),
            pending: None,
            fields: Some(fields),
        })
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct seq tuple tuple_struct enum identifier
    }
}

struct DocumentAccess<'de> {
    input: &'de str,
    blocks: Blocks<'de>,
    pending: Option<Block<'de>>,
    fields: Option<&'static [&'static str]>,
}

impl<'de> MapAccess<'de> for DocumentAccess<'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Error>
    where
        K: DeserializeSeed<'de>,
    {
        while let Some(block) = self.blocks.next() {
            if seen_block_before(self.input, block) {
                continue;
            }
            self.pending = Some(block);
            let name = self
                .fields
                .map(|fields| canonical_field_name(block.name, fields))
                .unwrap_or(block.name);
            let key = seed.deserialize(BorrowedStrDeserializer::<Error>::new(name))?;
            return Ok(Some(key));
        }
        Ok(None)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Error>
    where
        V: DeserializeSeed<'de>,
    {
        let block = self
            .pending
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Serde))?;
        seed.deserialize(SectionGroupDeserializer {
            input: self.input,
            first: block,
        })
        .map_err(|error| error.locate(block.line, block.column))
    }
}

#[derive(Clone, Copy)]
struct SectionGroupDeserializer<'de> {
    input: &'de str,
    first: Block<'de>,
}

impl<'de> SectionGroupDeserializer<'de> {
    fn one(self) -> Result<SingleSectionDeserializer<'de>, Error> {
        if matching_block_count(self.input, self.first.name) != 1 {
            return Err(Error::at(
                ErrorKind::DuplicateSection,
                self.first.line,
                self.first.column,
            ));
        }
        Ok(SingleSectionDeserializer {
            input: self.input,
            block: self.first,
        })
    }
}

impl<'de> de::Deserializer<'de> for SectionGroupDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        if matching_block_count(self.input, self.first.name) == 1 {
            self.one()?.deserialize_map(visitor)
        } else {
            self.deserialize_seq(visitor)
        }
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.one()?.deserialize_map(visitor)
    }

    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.one()?.deserialize_struct(name, fields, visitor)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SectionSequence {
            input: self.input,
            blocks: Blocks::new(self.input),
            name: self.first.name,
        })
    }

    fn deserialize_tuple<V>(self, _length: usize, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _length: usize,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_some(self)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct enum identifier
    }
}

struct SectionSequence<'de> {
    input: &'de str,
    blocks: Blocks<'de>,
    name: &'de str,
}

impl<'de> SeqAccess<'de> for SectionSequence<'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
    where
        T: DeserializeSeed<'de>,
    {
        while let Some(block) = self.blocks.next() {
            if block.name.eq_ignore_ascii_case(self.name) {
                let value = seed
                    .deserialize(SingleSectionDeserializer {
                        input: self.input,
                        block,
                    })
                    .map_err(|error| error.locate(block.line, block.column))?;
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(matching_block_count(self.input, self.name))
    }
}

#[derive(Clone, Copy)]
struct SingleSectionDeserializer<'de> {
    input: &'de str,
    block: Block<'de>,
}

impl<'de> de::Deserializer<'de> for SingleSectionDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(SectionAccess {
            input: self.input,
            block: self.block,
            properties: Properties::new(self.input, self.block),
            pending: None,
            fields: None,
        })
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(SectionAccess {
            input: self.input,
            block: self.block,
            properties: Properties::new(self.input, self.block),
            pending: None,
            fields: Some(fields),
        })
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct seq tuple tuple_struct enum identifier
    }
}

struct SectionAccess<'de> {
    input: &'de str,
    block: Block<'de>,
    properties: Properties<'de>,
    pending: Option<Property<'de>>,
    fields: Option<&'static [&'static str]>,
}

impl<'de> MapAccess<'de> for SectionAccess<'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Error>
    where
        K: DeserializeSeed<'de>,
    {
        while let Some(property) = self.properties.next() {
            if seen_property_before(self.input, self.block, property) {
                continue;
            }
            self.pending = Some(property);
            let name = self
                .fields
                .map(|fields| canonical_field_name(property.key, fields))
                .unwrap_or(property.key);
            let key = seed.deserialize(BorrowedStrDeserializer::<Error>::new(name))?;
            return Ok(Some(key));
        }
        Ok(None)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Error>
    where
        V: DeserializeSeed<'de>,
    {
        let property = self
            .pending
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Serde))?;
        seed.deserialize(PropertyGroupDeserializer {
            input: self.input,
            block: self.block,
            first: property,
        })
        .map_err(|error| error.locate(property.line, property.value_column))
    }
}

#[derive(Clone, Copy)]
struct PropertyGroupDeserializer<'de> {
    input: &'de str,
    block: Block<'de>,
    first: Property<'de>,
}

impl<'de> PropertyGroupDeserializer<'de> {
    fn scalar(self) -> Result<ScalarDeserializer<'de>, Error> {
        if matching_property_count(self.input, self.block, self.first.key) != 1 {
            return Err(Error::at(
                ErrorKind::DuplicateKey,
                self.first.line,
                self.first.key_column,
            ));
        }
        Ok(ScalarDeserializer::from_property(self.first))
    }

    fn unsupported(self) -> Error {
        Error::at(
            ErrorKind::UnsupportedType,
            self.first.line,
            self.first.value_column,
        )
    }
}

macro_rules! scalar_method {
    ($method:ident) => {
        fn $method<V>(self, visitor: V) -> Result<V::Value, Error>
        where
            V: Visitor<'de>,
        {
            self.scalar()?.$method(visitor)
        }
    };
}

impl<'de> de::Deserializer<'de> for PropertyGroupDeserializer<'de> {
    type Error = Error;

    scalar_method!(deserialize_any);
    scalar_method!(deserialize_bool);
    scalar_method!(deserialize_i8);
    scalar_method!(deserialize_i16);
    scalar_method!(deserialize_i32);
    scalar_method!(deserialize_i64);
    scalar_method!(deserialize_i128);
    scalar_method!(deserialize_u8);
    scalar_method!(deserialize_u16);
    scalar_method!(deserialize_u32);
    scalar_method!(deserialize_u64);
    scalar_method!(deserialize_u128);
    scalar_method!(deserialize_f32);
    scalar_method!(deserialize_f64);
    scalar_method!(deserialize_char);
    scalar_method!(deserialize_str);
    scalar_method!(deserialize_string);
    scalar_method!(deserialize_bytes);
    scalar_method!(deserialize_byte_buf);
    scalar_method!(deserialize_option);
    scalar_method!(deserialize_unit);
    scalar_method!(deserialize_identifier);

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.scalar()?.deserialize_enum(name, variants, visitor)
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.scalar()?.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(ValueSequence::new(self.input, self.block, self.first.key))
    }

    fn deserialize_tuple<V>(self, _length: usize, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _length: usize,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

#[derive(Clone, Copy)]
struct ScalarDeserializer<'de> {
    value: &'de str,
    line: usize,
    column: usize,
}

impl<'de> ScalarDeserializer<'de> {
    const fn from_property(property: Property<'de>) -> Self {
        Self {
            value: property.value,
            line: property.line,
            column: property.value_column,
        }
    }

    fn parse<T: FromStr>(&self, kind: ErrorKind) -> Result<T, Error> {
        self.value
            .parse()
            .map_err(|_| Error::at(kind, self.line, self.column))
    }

    fn unsupported(&self) -> Error {
        Error::at(ErrorKind::UnsupportedType, self.line, self.column)
    }
}

macro_rules! parse_number {
    ($method:ident, $visit:ident, $ty:ty, $kind:expr) => {
        fn $method<V>(self, visitor: V) -> Result<V::Value, Error>
        where
            V: Visitor<'de>,
        {
            visitor
                .$visit::<Error>(self.parse::<$ty>($kind)?)
                .map_err(|error| error.locate(self.line, self.column))
        }
    };
}

impl<'de> de::Deserializer<'de> for ScalarDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        let value = if self.value.eq_ignore_ascii_case("true")
            || self.value.eq_ignore_ascii_case("yes")
            || self.value.eq_ignore_ascii_case("on")
            || self.value == "1"
        {
            true
        } else if self.value.eq_ignore_ascii_case("false")
            || self.value.eq_ignore_ascii_case("no")
            || self.value.eq_ignore_ascii_case("off")
            || self.value == "0"
        {
            false
        } else {
            return Err(Error::at(ErrorKind::InvalidBoolean, self.line, self.column));
        };
        visitor
            .visit_bool::<Error>(value)
            .map_err(|error| error.locate(self.line, self.column))
    }

    parse_number!(deserialize_i8, visit_i8, i8, ErrorKind::InvalidInteger);
    parse_number!(deserialize_i16, visit_i16, i16, ErrorKind::InvalidInteger);
    parse_number!(deserialize_i32, visit_i32, i32, ErrorKind::InvalidInteger);
    parse_number!(deserialize_i64, visit_i64, i64, ErrorKind::InvalidInteger);
    parse_number!(
        deserialize_i128,
        visit_i128,
        i128,
        ErrorKind::InvalidInteger
    );
    parse_number!(
        deserialize_u8,
        visit_u8,
        u8,
        ErrorKind::InvalidUnsignedInteger
    );
    parse_number!(
        deserialize_u16,
        visit_u16,
        u16,
        ErrorKind::InvalidUnsignedInteger
    );
    parse_number!(
        deserialize_u32,
        visit_u32,
        u32,
        ErrorKind::InvalidUnsignedInteger
    );
    parse_number!(
        deserialize_u64,
        visit_u64,
        u64,
        ErrorKind::InvalidUnsignedInteger
    );
    parse_number!(
        deserialize_u128,
        visit_u128,
        u128,
        ErrorKind::InvalidUnsignedInteger
    );
    parse_number!(deserialize_f32, visit_f32, f32, ErrorKind::InvalidFloat);
    parse_number!(deserialize_f64, visit_f64, f64, ErrorKind::InvalidFloat);

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        let mut chars = self.value.chars();
        let value = chars
            .next()
            .filter(|_| chars.next().is_none())
            .ok_or_else(|| Error::at(ErrorKind::InvalidChar, self.line, self.column))?;
        visitor
            .visit_char::<Error>(value)
            .map_err(|error| error.locate(self.line, self.column))
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor
            .visit_borrowed_str::<Error>(self.value)
            .map_err(|error| error.locate(self.line, self.column))
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor
            .visit_borrowed_bytes::<Error>(self.value.as_bytes())
            .map_err(|error| error.locate(self.line, self.column))
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor
            .visit_some(self)
            .map_err(|error| error.locate(self.line, self.column))
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        if self.value.is_empty() {
            visitor
                .visit_unit::<Error>()
                .map_err(|error| error.locate(self.line, self.column))
        } else {
            Err(self.unsupported())
        }
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor
            .visit_newtype_struct(self)
            .map_err(|error| error.locate(self.line, self.column))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor
            .visit_enum(ScalarEnum { scalar: self })
            .map_err(|error| error.locate(self.line, self.column))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }

    fn deserialize_tuple<V>(self, _length: usize, _visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _length: usize,
        _visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }
}

struct ScalarEnum<'de> {
    scalar: ScalarDeserializer<'de>,
}

impl<'de> EnumAccess<'de> for ScalarEnum<'de> {
    type Error = Error;
    type Variant = ScalarDeserializer<'de>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Error>
    where
        V: DeserializeSeed<'de>,
    {
        let variant = seed.deserialize(BorrowedStrDeserializer::<Error>::new(self.scalar.value))?;
        Ok((variant, self.scalar))
    }
}

impl<'de> VariantAccess<'de> for ScalarDeserializer<'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Error>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(self)
    }

    fn tuple_variant<V>(self, _length: usize, _visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(self.unsupported())
    }
}

struct ValueSequence<'de> {
    properties: Properties<'de>,
    key: &'de str,
    current: Option<Property<'de>>,
    remainder: &'de str,
}

impl<'de> ValueSequence<'de> {
    fn new(input: &'de str, block: Block<'de>, key: &'de str) -> Self {
        Self {
            properties: Properties::new(input, block),
            key,
            current: None,
            remainder: "",
        }
    }

    fn next_item(&mut self) -> Option<ScalarDeserializer<'de>> {
        loop {
            if let Some(property) = self.current {
                if !self.remainder.is_empty() {
                    let (item, rest) = match self.remainder.split_once(',') {
                        Some((item, rest)) => (item, rest),
                        None => (self.remainder, ""),
                    };
                    let leading = item.len() - item.trim_start().len();
                    let value = item.trim();
                    let consumed = property.value.len() - self.remainder.len();
                    self.remainder = rest;
                    if value.is_empty() {
                        continue;
                    }
                    return Some(ScalarDeserializer {
                        value,
                        line: property.line,
                        column: property.value_column + consumed + leading,
                    });
                }
                self.current = None;
            }

            let property = loop {
                let next = self.properties.next()?;
                if next.key.eq_ignore_ascii_case(self.key) {
                    break next;
                }
            };
            if property.value.is_empty() {
                continue;
            }
            self.remainder = property.value;
            self.current = Some(property);
        }
    }
}

impl<'de> SeqAccess<'de> for ValueSequence<'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
    where
        T: DeserializeSeed<'de>,
    {
        let Some(item) = self.next_item() else {
            return Ok(None);
        };
        seed.deserialize(item)
            .map(Some)
            .map_err(|error| error.locate(item.line, item.column))
    }
}
