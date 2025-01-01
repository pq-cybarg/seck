//! Parse `strace -f` output lines into the `Effect` grammar.
//!
//! This is intentionally permissive: we only recognise the syscalls we
//! care about (openat / openat2 / execve / execveat / read / write /
//! connect); everything else is ignored. The parser is also designed to
//! survive arbitrary garbage — `cargo fuzz` drives it with random input
//! and asserts no panic.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    OpenP {
        path: Vec<u8>,
    },
    ExecP {
        path: Vec<u8>,
        args: Vec<Vec<u8>>,
        env: Vec<(Vec<u8>, Vec<u8>)>,
    },
    ReadF {
        fd: i32,
    },
    WriteF {
        fd: i32,
        bytes: Vec<u8>,
    },
    NetConn {
        host: String,
        port: u16,
    },
}

pub fn parse_strace(input: &str) -> Vec<Effect> {
    input.lines().filter_map(parse_line).collect()
}

/// Strip `[pid 1234]` prefix and any leading whitespace.
fn strip_pid_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            return rest[idx + 1..].trim_start();
        }
    }
    trimmed
}

fn parse_line(line: &str) -> Option<Effect> {
    let body = strip_pid_prefix(line);

    if let Some(args) = body.strip_prefix("openat(") {
        // openat(AT_FDCWD, "<path>", flags) — path is the 1st quoted string
        let path = nth_quoted_string(args, 0)?;
        return Some(Effect::OpenP {
            path: path.into_bytes(),
        });
    }
    if let Some(args) = body.strip_prefix("openat2(") {
        let path = nth_quoted_string(args, 0)?;
        return Some(Effect::OpenP {
            path: path.into_bytes(),
        });
    }
    if let Some(args) = body.strip_prefix("execve(") {
        // execve("<path>", argv, envp)
        let path = nth_quoted_string(args, 0)?;
        return Some(Effect::ExecP {
            path: path.into_bytes(),
            args: vec![],
            env: vec![],
        });
    }
    if let Some(args) = body.strip_prefix("execveat(") {
        // execveat(dirfd, "<path>", argv, envp, flags)
        let path = nth_quoted_string(args, 0)?;
        return Some(Effect::ExecP {
            path: path.into_bytes(),
            args: vec![],
            env: vec![],
        });
    }
    if let Some(args) = body.strip_prefix("write(") {
        let fd: i32 = first_token_int(args)?;
        let bytes_str = nth_quoted_string(args, 0)?;
        return Some(Effect::WriteF {
            fd,
            bytes: bytes_str.into_bytes(),
        });
    }
    if let Some(args) = body.strip_prefix("read(") {
        let fd: i32 = first_token_int(args)?;
        return Some(Effect::ReadF { fd });
    }
    if let Some(args) = body.strip_prefix("connect(") {
        let host = args.find("inet_addr(\"").and_then(|i| {
            let s = &args[i + 11..];
            let end = s.find('"')?;
            Some(s[..end].to_string())
        })?;
        let port: u16 = args.find("htons(").and_then(|i| {
            let s = &args[i + 6..];
            let end = s.find(')')?;
            s[..end].parse().ok()
        })?;
        return Some(Effect::NetConn { host, port });
    }
    None
}

/// Return the integer value of the first comma-separated argument.
fn first_token_int(args: &str) -> Option<i32> {
    args.split(',').next()?.trim().parse().ok()
}

/// Return the n-th (0-indexed) quoted string within `args`.
fn nth_quoted_string(args: &str, n: usize) -> Option<String> {
    let mut count = 0usize;
    let bytes = args.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // start of a quoted string; find closing quote, respecting backslash escapes
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                    continue;
                }
                if bytes[j] == b'"' {
                    if count == n {
                        return Some(String::from_utf8_lossy(&bytes[start..j]).into_owned());
                    }
                    count += 1;
                    i = j + 1;
                    break;
                }
                j += 1;
            }
            if j >= bytes.len() {
                return None;
            }
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openat() {
        let line = r#"openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3"#;
        assert_eq!(
            parse_line(line),
            Some(Effect::OpenP {
                path: b"/etc/hosts".to_vec()
            })
        );
    }

    #[test]
    fn strips_pid_prefix() {
        let line = r#"[pid 1234] openat(AT_FDCWD, "/x", O_RDONLY) = 3"#;
        assert_eq!(
            parse_line(line),
            Some(Effect::OpenP {
                path: b"/x".to_vec()
            })
        );
    }

    #[test]
    fn parses_execve() {
        let line = r#"execve("/usr/bin/ls", ["ls", "-la"], 0x7ffd) = 0"#;
        assert_eq!(
            parse_line(line),
            Some(Effect::ExecP {
                path: b"/usr/bin/ls".to_vec(),
                args: vec![],
                env: vec![],
            })
        );
    }

    #[test]
    fn parses_write() {
        let line = r#"write(3, "hello", 5) = 5"#;
        assert_eq!(
            parse_line(line),
            Some(Effect::WriteF {
                fd: 3,
                bytes: b"hello".to_vec()
            })
        );
    }

    #[test]
    fn parses_connect() {
        let line = r#"connect(7, {sa_family=AF_INET, sin_addr=inet_addr("1.2.3.4"), sin_port=htons(80)}, 16) = 0"#;
        assert_eq!(
            parse_line(line),
            Some(Effect::NetConn {
                host: "1.2.3.4".into(),
                port: 80
            })
        );
    }

    #[test]
    fn random_garbage_does_not_panic() {
        // Quick smoke for the fuzz invariant.
        for s in [
            "",
            "garbage",
            r#"openat("#,
            r#"connect(7, {sa_family=AF_INET},)"#,
            r#"write(notanumber, "x", 1)"#,
        ] {
            let _ = parse_line(s);
        }
    }
}
