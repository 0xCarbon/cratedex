//! Cross-platform service management for cratedex.

use crate::config::is_loopback_host;
use std::path::PathBuf;
use std::process::Command;

const SERVICE_NAME: &str = "cratedex";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceInstallScope {
    CurrentUser,
    System { run_as: String },
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub exec_path: PathBuf,
    pub host: String,
    pub port: u16,
    pub allow_remote: bool,
    pub linger: bool,
    pub scope: ServiceInstallScope,
}

trait ServiceManager {
    fn install(&self, config: &ServiceConfig) -> anyhow::Result<()>;
    fn remove(&self, scope: ServiceInstallScope) -> anyhow::Result<()>;
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

fn current_exec_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from(SERVICE_NAME))
}

pub fn installed_services() -> Vec<ServiceInstallScope> {
    let mut scopes = Vec::new();
    let current_user = ServiceInstallScope::CurrentUser;
    let system = ServiceInstallScope::System {
        run_as: String::new(),
    };

    if is_service_installed(&current_user) {
        scopes.push(current_user);
    }
    if is_service_installed(&system) {
        scopes.push(system);
    }

    scopes
}

#[allow(clippy::needless_return)]
pub fn restart_service(scope: &ServiceInstallScope) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::restart_service(scope);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::restart_service(scope);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::restart_service(scope);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = scope;
        anyhow::bail!("Service management is not supported on this platform");
    }
}

#[allow(clippy::needless_return)]
pub fn refresh_system_binary() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::refresh_system_binary();
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("System service binary refresh is only implemented for Linux.");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn is_service_installed(scope: &ServiceInstallScope) -> bool {
    linux::service_is_installed(scope)
}

#[cfg(target_os = "macos")]
pub fn is_service_installed(scope: &ServiceInstallScope) -> bool {
    macos::service_is_installed(scope)
}

#[cfg(target_os = "windows")]
pub fn is_service_installed(scope: &ServiceInstallScope) -> bool {
    windows::service_is_installed(scope)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn is_service_installed(_scope: &ServiceInstallScope) -> bool {
    false
}

#[allow(clippy::needless_return)]
pub fn install_service(
    host: &str,
    port: u16,
    linger: bool,
    allow_remote: bool,
    scope: ServiceInstallScope,
) -> anyhow::Result<()> {
    if !allow_remote && !is_loopback_host(host) {
        anyhow::bail!(
            "Refusing to generate a service for non-loopback host '{}'. \
Use --allow-remote only when fronting cratedex with an authenticated TLS reverse proxy.",
            host
        );
    }

    #[cfg(not(target_os = "linux"))]
    if linger {
        anyhow::bail!("The --linger flag is only supported on Linux (systemd).");
    }

    let config = ServiceConfig {
        exec_path: current_exec_path(),
        host: host.to_string(),
        port,
        allow_remote,
        linger,
        scope,
    };

    #[cfg(target_os = "linux")]
    {
        return linux::LinuxServiceManager.install(&config);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::MacosServiceManager.install(&config);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::WindowsServiceManager.install(&config);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Service management is not supported on this platform");
    }
}

pub(crate) fn require_root(action_desc: &str, exec_start: &str) -> anyhow::Result<()> {
    let euid = Command::new("id").args(["-u"]).output().ok();
    let is_root = euid
        .as_ref()
        .and_then(|o| std::str::from_utf8(&o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        anyhow::bail!(
            "{action_desc} requires root.\n\
\n\
Try:\n\
  sudo {exec_start} {action_desc}\n\
  sudo \"$(command -v cratedex)\" {action_desc}"
        );
    }
    Ok(())
}

#[allow(clippy::needless_return)]
pub fn remove_service(scope: ServiceInstallScope) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::LinuxServiceManager.remove(scope);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::MacosServiceManager.remove(scope);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::WindowsServiceManager.remove(scope);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = scope;
        anyhow::bail!("Service management is not supported on this platform");
    }
}
