use std::borrow::Cow;

pub(super) const NON_ASCII_BYTE: char = '\u{7f}';
pub(super) const EXCLUDED_FF_BYTE: char = '\u{1f}';

/// Length-preserving byte view used by the parser. Non-ASCII bytes become
/// reserved, non-APRS bytes that cannot be mistaken for protocol punctuation;
/// their final public rendering is handled in one place after parsing.
pub(super) struct ParserView<'a> {
    bytes: Cow<'a, [u8]>,
}

impl<'a> ParserView<'a> {
    pub(super) fn from_bytes(raw: &'a [u8]) -> Self {
        let bytes = if raw.is_ascii() {
            Cow::Borrowed(raw)
        } else {
            Cow::Owned(
                raw.iter()
                    .map(|byte| match *byte {
                        byte if byte.is_ascii() => byte,
                        0xff => EXCLUDED_FF_BYTE as u8,
                        _ => NON_ASCII_BYTE as u8,
                    })
                    .collect(),
            )
        };
        Self { bytes }
    }

    pub(super) fn into_text(self) -> Cow<'a, str> {
        match self.bytes {
            Cow::Borrowed(bytes) => {
                Cow::Borrowed(std::str::from_utf8(bytes).expect("parser view is ASCII"))
            }
            Cow::Owned(bytes) => {
                Cow::Owned(String::from_utf8(bytes).expect("parser view is ASCII"))
            }
        }
    }
}
