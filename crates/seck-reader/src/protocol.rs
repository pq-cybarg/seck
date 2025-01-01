//! Parser for the `seck-proto` wire format on the reader side.

use seck_proto::{
    MAGIC_HEADER, MAGIC_TRAILER, MAX_ENTRIES, MAX_ENTRY_BYTES, MAX_PATH_LEN, ProtoError, VERSION,
};
use std::io::Read;

pub struct Frame {
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

pub fn read_frames(reader: &mut impl Read) -> Result<Vec<Frame>, ProtoError> {
    let mut buf4 = [0u8; 4];
    let mut buf2 = [0u8; 2];
    let mut buf8 = [0u8; 8];

    reader.read_exact(&mut buf4)?;
    if &buf4 != MAGIC_HEADER {
        return Err(ProtoError::BadMagic);
    }
    reader.read_exact(&mut buf2)?;
    let v = u16::from_le_bytes(buf2);
    if v != VERSION {
        return Err(ProtoError::BadVersion(v));
    }
    reader.read_exact(&mut buf2)?; // reserved
    reader.read_exact(&mut buf4)?;
    let n = u32::from_le_bytes(buf4);
    if n > MAX_ENTRIES {
        return Err(ProtoError::TooLarge(n as u64));
    }

    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        reader.read_exact(&mut buf4)?;
        let pl = u32::from_le_bytes(buf4);
        if pl > MAX_PATH_LEN {
            return Err(ProtoError::TooLarge(pl as u64));
        }
        let mut path = vec![0u8; pl as usize];
        reader.read_exact(&mut path)?;
        let relative_path = String::from_utf8(path).map_err(|_| ProtoError::BadPath)?;
        reader.read_exact(&mut buf8)?;
        let bl = u64::from_le_bytes(buf8);
        if bl > MAX_ENTRY_BYTES {
            return Err(ProtoError::TooLarge(bl));
        }
        let mut bytes = vec![0u8; bl as usize];
        reader.read_exact(&mut bytes)?;
        out.push(Frame { relative_path, bytes });
    }
    reader.read_exact(&mut buf4)?;
    if &buf4 != MAGIC_TRAILER {
        return Err(ProtoError::BadMagic);
    }
    Ok(out)
}
