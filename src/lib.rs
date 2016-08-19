// Copyright (c) 2016 csrf developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

//! CSRF token library inspired by golang's [gorilla/csrf](https://github.com/gorilla/csrf).

extern crate base64;
extern crate byteorder;
extern crate rand;

use byteorder::{LittleEndian, ReadBytesExt};
use rand::Rng;
use std::fmt;
use std::io::Cursor;
use std::mem;
use std::slice;
use std::error::Error;

/// Error type for wrapping errors that can happen during base64 decoding.
#[derive(Debug)]
pub struct Base64DecodeError(pub String);

/// Actual token that `PaddedToken`s are compared against. Meant to be stored in the server session.
#[derive(Debug, Default, PartialEq)]
pub struct Token(u32);
impl Token {
    /// Creates a new `Token` using operating system's random number generator.
    pub fn new() -> Token {
        let mut rng = rand::os::OsRng::new().unwrap();
        Token(rng.next_u32())
    }
    /// Creates a new `Token` from a base64 encoded string
    pub fn from_base64_str(base64: &str) -> Result<Token, Base64DecodeError> {
        let mut bytes = Cursor::new(try!(base64::decode(base64)
            .map_err(|e| Base64DecodeError(e.description().into()))));
        let token = try!(bytes.read_u32::<LittleEndian>()
            .map_err(|e| Base64DecodeError(e.description().into())));
        Ok(Token(token))
    }
}
impl<'a> Into<&'a [u8]> for &'a Token {
    fn into(self) -> &'a [u8] {
        unsafe {
            slice::from_raw_parts(&self.0 as *const u32 as *const u8,
                                  mem::size_of_val(&self.0))
        }
    }
}
impl fmt::Display for Token {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", base64::encode(self.into()))
    }
}

/// A token that can be used in HTML forms.
/// A compromise is made between security and convenience in a way that every
/// token is different, but all the data needed for decoding the real token is present.
/// `PaddedToken` internally is a 32-bit one-time token concatenated with the real `Token` that is
/// XOR'd with the one-time token.
#[derive(Debug, PartialEq)]
pub struct PaddedToken(u64);
impl PaddedToken {
    /// Creates a new `PaddedToken` using operating system's random number generator.
    pub fn new(real_token: &Token) -> PaddedToken {
        let mut rng = rand::os::OsRng::new().unwrap();
        let otp = rng.next_u32();
        let masked = otp ^ real_token.0;
        PaddedToken(((otp as u64) << 32) | masked as u64)
    }
    /// Unmasks a `PaddedToken` and returning the underlying `Token`.
    pub fn unmask(&self) -> Token {
        let otp: u32 = (self.0 >> 32) as u32;
        let masked: u32 = (self.0 & 0xFFFFFFFF) as u32;
        Token(otp ^ masked)
    }
    /// Creates a new `PaddedToken` from a base64 encoded string
    pub fn from_base64_str(base64: &str) -> Result<PaddedToken, Base64DecodeError> {
        let mut bytes = Cursor::new(try!(base64::decode(base64)
            .map_err(|e| Base64DecodeError(e.description().into()))));
        let token = try!(bytes.read_u64::<LittleEndian>()
            .map_err(|e| Base64DecodeError(e.description().into())));
        Ok(PaddedToken(token))
    }
}
impl<'a> Into<&'a [u8]> for &'a PaddedToken {
    fn into(self) -> &'a [u8] {
        unsafe {
            slice::from_raw_parts(&self.0 as *const u64 as *const u8,
                                  mem::size_of_val(&self.0))
        }
    }
}
impl fmt::Display for PaddedToken {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", base64::encode(self.into()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn masking_and_unmasking_produces_same_token() {
        let token = ::Token::new();
        let padded_token = ::PaddedToken::new(&token);
        let unmasked = padded_token.unmask();
        assert!(unmasked == token);
    }
    #[test]
    fn base64_encode_and_decode_token() {
        let token = ::Token::new();
        let base64 = format!("{}", token);
        let base64_decoded = ::Token::from_base64_str(&base64).ok().unwrap();
        assert!(token == base64_decoded);
    }
    #[test]
    fn base64_encode_and_decode_paddedtoken() {
        let token = ::Token::new();
        let padded_token = ::PaddedToken::new(&token);
        let base64 = format!("{}", padded_token);
        let base64_decoded = ::PaddedToken::from_base64_str(&base64).ok().unwrap();
        assert!(padded_token == base64_decoded);
    }
}
