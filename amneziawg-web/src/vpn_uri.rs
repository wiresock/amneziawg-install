//! AmneziaVPN import envelope: Qt qCompress framing, then unpadded Base64URL.
//! Encode the existing config verbatim so protocol extensions are preserved.

use std::io::{self, Write};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::{write::ZlibEncoder, Compression};

pub fn encode(config: &[u8]) -> io::Result<String> {
    let length = u32::try_from(config.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "config exceeds the import format limit",
        )
    })?;
    // qCompress prefixes the zlib stream with the uncompressed byte length in
    // network order. AmneziaVPN's importer calls qUncompress after decoding.
    let mut encoder = ZlibEncoder::new(length.to_be_bytes().to_vec(), Compression::new(8));
    encoder.write_all(config)?;
    Ok(format!(
        "vpn://{}",
        URL_SAFE_NO_PAD.encode(encoder.finish()?)
    ))
}
