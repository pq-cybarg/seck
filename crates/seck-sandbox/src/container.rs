//! Approach C: rootless-podman (preferred) or rootless-docker container
//! sandbox. The orchestrator pipes bytes into the running container's
//! FD 3 via `podman run --net=none --read-only --cap-drop=ALL ...`.
//!
//! We refuse rootful docker by default — that container model gives the
//! container superuser inside the host's user namespace, which is
//! exactly the privilege escalation Approach C is supposed to prevent.

use seck_plugin::SandboxBackend;
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Runtime {
    Podman(PathBuf),
    RootlessDocker(PathBuf),
    RootfulDocker(PathBuf),
}

#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("no container runtime found (install podman)")]
    NoRuntime,
    #[error("only rootful docker available; pass --insecure-rootful-docker to override")]
    OnlyRootfulDocker,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn detect_runtime(allow_insecure_rootful_docker: bool) -> Result<Runtime, DetectError> {
    if let Ok(p) = which("podman") {
        let out = std::process::Command::new(&p)
            .args(["info", "--format", "{{.Host.Security.Rootless}}"])
            .output()?;
        if out.status.success() && out.stdout.starts_with(b"true") {
            return Ok(Runtime::Podman(p));
        }
    }
    if let Ok(p) = which("docker") {
        let out = std::process::Command::new(&p)
            .args(["info", "--format", "{{.SecurityOptions}}"])
            .output()?;
        let rootless = String::from_utf8_lossy(&out.stdout).contains("rootless");
        if rootless {
            return Ok(Runtime::RootlessDocker(p));
        }
        if allow_insecure_rootful_docker {
            return Ok(Runtime::RootfulDocker(p));
        }
        return Err(DetectError::OnlyRootfulDocker);
    }
    Err(DetectError::NoRuntime)
}

/// Build the argv for `podman run` / `docker run` with the strictest
/// flags. Caller appends its own image-args (none in the entrypoint case).
pub fn build_args(rt: &Runtime, model_dir: &std::path::Path) -> Vec<String> {
    let _ = rt; // runtime selection doesn't change the flag set
    vec![
        "run".into(),
        "--rm".into(),
        "--network=none".into(),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--tmpfs=/tmp:noexec,nosuid,size=64m".into(),
        "--memory=2g".into(),
        "--pids-limit=64".into(),
        "--no-healthcheck".into(),
        "--hostname=seck-sandbox".into(),
        "--ipc=none".into(),
        "--cpus=1.0".into(),
        format!("--volume={}:/models:ro", model_dir.display()),
        "--userns=auto".into(),
        "-i".into(), // keep stdin open for FD inheritance
        "localhost/seck-reader:0.1.0".into(),
    ]
}

fn which(prog: &str) -> std::io::Result<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(prog);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{prog} not on PATH"),
    ))
}

pub struct ContainerSandbox {
    profile_hash: [u8; 32],
}

impl Default for ContainerSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerSandbox {
    pub fn new() -> Self {
        let mut h = Sha3_256::new();
        h.update(include_bytes!("../../../platform/container/Dockerfile"));
        h.update(include_bytes!("../../../platform/container/build.sh"));
        Self {
            profile_hash: h.finalize().into(),
        }
    }
}

impl SandboxBackend for ContainerSandbox {
    fn name(&self) -> &'static str {
        "container-podman"
    }
    fn profile_sha3_256(&self) -> [u8; 32] {
        self.profile_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_has_no_network_read_only_cap_drop_all() {
        let args = build_args(
            &Runtime::Podman(PathBuf::from("/usr/bin/podman")),
            std::path::Path::new("/tmp/model-dir"),
        );
        assert!(args.iter().any(|a| a == "--network=none"));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert!(args.iter().any(|a| a == "--cap-drop=ALL"));
        assert!(args.iter().any(|a| a == "--security-opt=no-new-privileges"));
        assert!(args.iter().any(|a| a == "--ipc=none"));
    }

    #[test]
    fn exactly_one_read_only_mount() {
        let args = build_args(
            &Runtime::Podman(PathBuf::from("/usr/bin/podman")),
            std::path::Path::new("/tmp/model-dir"),
        );
        let mounts: Vec<_> = args.iter().filter(|a| a.starts_with("--volume=")).collect();
        assert_eq!(mounts.len(), 1);
        assert!(mounts[0].ends_with(":ro"));
    }
}
