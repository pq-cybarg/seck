//! Wire format between `seck-reader-bytes` (sender — sees raw file bytes)
//! and `seck-reader-priv` (receiver — sees only this structured form).
//!
//! Line-delimited JSON. Each line is one `Message`. The byte process
//! builds the prompt entirely (including base64-encoded file content);
//! the priv process never sees a `Tainted<Vec<u8>>` because it doesn't
//! depend on `seck-taint`. Compile-fail test in
//! `tests/compile-fail/cases/priv_imports_seck_taint.rs` proves that.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Message {
    /// Header sent once at the start of each invocation.
    Header {
        nonce_hex: String,
        system_prompt: String,
        task_prompt: String,
    },
    /// One file. `content_base64` IS the base64 of the file bytes.
    /// The priv process never sees raw bytes — only this string.
    File {
        relative_path: String,
        content_base64: String,
        byte_count: u64,
    },
    /// Sent last; tells priv "no more files, run inference now".
    EndFiles,
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("unexpected EOF")]
    UnexpectedEof,
}

pub fn write_message<W: std::io::Write>(w: &mut W, m: &Message) -> Result<(), IpcError> {
    let line = serde_json::to_string(m)?;
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}

pub fn read_messages<R: std::io::BufRead>(r: &mut R) -> Result<Vec<Message>, IpcError> {
    let mut out = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let m: Message = serde_json::from_str(trimmed)?;
        let end = matches!(m, Message::EndFiles);
        out.push(m);
        if end {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip() {
        let msgs = vec![
            Message::Header {
                nonce_hex: "ab".repeat(32),
                system_prompt: "be passive".into(),
                task_prompt: "emit JSON".into(),
            },
            Message::File {
                relative_path: "a.rs".into(),
                content_base64: "aGVsbG8=".into(),
                byte_count: 5,
            },
            Message::EndFiles,
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            write_message(&mut buf, m).unwrap();
        }
        let mut cur = Cursor::new(&buf);
        let back = read_messages(&mut cur).unwrap();
        assert_eq!(back.len(), 3);
        match (&msgs[0], &back[0]) {
            (Message::Header { nonce_hex: a, .. }, Message::Header { nonce_hex: b, .. }) => {
                assert_eq!(a, b)
            }
            _ => panic!("type mismatch"),
        }
    }

    #[test]
    fn stops_at_end_files() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Message::EndFiles).unwrap();
        // Garbage AFTER EndFiles must be ignored.
        buf.extend_from_slice(b"this would be a JSON parse error\n");
        let mut cur = Cursor::new(&buf);
        let msgs = read_messages(&mut cur).unwrap();
        assert_eq!(msgs.len(), 1);
    }
}
