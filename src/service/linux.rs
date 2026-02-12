use super::{SERVICE_NAME, ServiceConfig, ServiceInstallScope, ServiceManager, require_root};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(8);

pub struct LinuxServiceManager;

impl ServiceManager for LinuxServiceManager {
    fn install(&self, config: &ServiceConfig) -> anyhow::Result<()> {
        if matches!(config.scope, ServiceInstallScope::System { .. }) && config.linger {
            anyhow::bail!("The --linger flag is only supported for per-user services.");
        }

        let path = service_file_path(&config.scope)?;
        let exec_start = config.exec_path.to_string_lossy().to_string();

        let content = match &config.scope {
            ServiceInstallScope::System { run_as } => system_service_unit_content(
                &exec_start,
                &config.host,
                config.port,
                run_as,
                config.allow_remote,
            )?,
            ServiceInstallScope::CurrentUser => {
                service_unit_content(&exec_start, &config.host, config.port, config.allow_remote)
            }
        };

        if let ServiceInstallScope::System { .. } = &config.scope {
            require_root("install-service --system", &exec_start)?;
        }

        let needs_write = match std::fs::read_to_string(&path) {
            Ok(existing) => existing != content,
            Err(_) => true,
        };

        if needs_write {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if let Err(e) = std::fs::write(&path, &content) {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    anyhow::bail!("Failed to write {}: {e}. Re-run with sudo.", path.display());
                }
                return Err(e.into());
            }
            eprintln!("Wrote {}", path.display());
        } else {
            eprintln!("Service file unchanged at {}", path.display());
        }

        match &config.scope {
            ServiceInstallScope::CurrentUser => {
                systemctl_user(&["daemon-reload"])?;
                systemctl_user(&["enable", SERVICE_NAME])?;
                systemctl_user(&["restart", SERVICE_NAME])?;
                eprintln!(
                    "Service {SERVICE_NAME} is now enabled and running for the current user."
                );

                if config.linger {
                    let user = std::env::var("USER").unwrap_or_default();
                    if !user.is_empty() {
                        let status = Command::new("loginctl")
                            .args(["enable-linger", &user])
                            .status()?;
                        if status.success() {
                            eprintln!("Linger enabled for user {user}.");
                        } else {
                            eprintln!("Warning: loginctl enable-linger failed (exit {status}).");
                        }
                    }
                }
            }
            ServiceInstallScope::System { run_as } => {
                systemctl_system(&["daemon-reload"])?;
                systemctl_system(&["enable", SERVICE_NAME])?;
                systemctl_system(&["restart", SERVICE_NAME])?;
                eprintln!(
                    "System service {SERVICE_NAME} is now enabled and running (User={run_as}).\n\
Check status with: systemctl status {SERVICE_NAME}"
                );
            }
        }

        Ok(())
    }

    fn remove(&self, scope: ServiceInstallScope) -> anyhow::Result<()> {
        let path = service_file_path(&scope)?;
        let exec_start = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| SERVICE_NAME.to_string());

        match &scope {
            ServiceInstallScope::CurrentUser => {
                let _ = systemctl_user(&["stop", SERVICE_NAME]);
                let _ = systemctl_user(&["disable", SERVICE_NAME]);

                if path.exists() {
                    std::fs::remove_file(&path)?;
                    eprintln!("Removed {}", path.display());
                } else {
                    eprintln!("Service file not found at {}", path.display());
                }

                systemctl_user(&["daemon-reload"])?;
                eprintln!("Service {SERVICE_NAME} removed for the current user.");
            }
            ServiceInstallScope::System { .. } => {
                require_root("remove-service --system", &exec_start)?;

                let _ = systemctl_system(&["stop", SERVICE_NAME]);
                let _ = systemctl_system(&["disable", SERVICE_NAME]);

                if path.exists() {
                    std::fs::remove_file(&path)?;
                    eprintln!("Removed {}", path.display());
                } else {
                    eprintln!("Service file not found at {}", path.display());
                }

                systemctl_system(&["daemon-reload"])?;
                eprintln!("System service {SERVICE_NAME} removed.");
            }
        }

        Ok(())
    }
}

fn systemd_quote_arg(s: &str) -> String {
    if !s.contains([' ', '\t', '\n', '"', '\\']) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn service_unit_content(exec_start: &str, host: &str, port: u16, allow_remote: bool) -> String {
    let exec_start = systemd_quote_arg(exec_start);
    format!(
        r#"[Unit]
Description=Cratedex shared HTTP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=CRATEDEX__SERVER__TRANSPORT=http
Environment=CRATEDEX__SERVER__HOST={host}
Environment=CRATEDEX__SERVER__PORT={port}
Environment=CRATEDEX__SERVER__ALLOW_REMOTE={allow_remote}
ExecStart={exec_start} server
Restart=on-failure
RestartSec=2
TimeoutStartSec=120
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectClock=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
SystemCallArchitectures=native
ProtectSystem=full
UMask=0077
LimitNOFILE=16384
TasksMax=512

[Install]
WantedBy=default.target
"#
    )
}

fn system_service_unit_content(
    exec_start: &str,
    host: &str,
    port: u16,
    run_as: &str,
    allow_remote: bool,
) -> anyhow::Result<String> {
    let exec_start = systemd_quote_arg(exec_start);
    let home_dir = resolve_user_home(run_as)?;
    let home_dir = home_dir.to_string_lossy();
    let target_triple = env!("TARGET");
    Ok(format!(
        r#"[Unit]
Description=Cratedex shared HTTP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={run_as}
Group={run_as}
Environment=CRATEDEX__SERVER__TRANSPORT=http
Environment=CRATEDEX__SERVER__HOST={host}
Environment=CRATEDEX__SERVER__PORT={port}
Environment=CRATEDEX__SERVER__ALLOW_REMOTE={allow_remote}
Environment=PATH={home_dir}/.cargo/bin:{home_dir}/.rustup/toolchains/stable-{target_triple}/bin:/usr/local/bin:/usr/bin:/bin
ExecStart={exec_start} server
Restart=on-failure
RestartSec=2
TimeoutStartSec=120
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectClock=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
SystemCallArchitectures=native
ProtectSystem=full
UMask=0077
LimitNOFILE=16384
TasksMax=512

[Install]
WantedBy=multi-user.target
"#
    ))
}

fn resolve_user_home(username: &str) -> anyhow::Result<PathBuf> {
    if username.is_empty() {
        anyhow::bail!("run-as user cannot be empty");
    }

    if let Ok(output) = Command::new("getent").args(["passwd", username]).output()
        && output.status.success()
    {
        let line = String::from_utf8_lossy(&output.stdout);
        if let Some(home) = line.split(':').nth(5)
            && !home.trim().is_empty()
        {
            return Ok(PathBuf::from(home.trim()));
        }
    }

    let passwd = std::fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        if line.starts_with(&format!("{username}:")) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 && !parts[5].is_empty() {
                return Ok(PathBuf::from(parts[5]));
            }
        }
    }

    anyhow::bail!("Could not resolve home directory for user {username}")
}

fn service_file_path(scope: &ServiceInstallScope) -> anyhow::Result<PathBuf> {
    match scope {
        ServiceInstallScope::CurrentUser => {
            let home =
                dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
            Ok(home
                .join(".config")
                .join("systemd")
                .join("user")
                .join(format!("{SERVICE_NAME}.service")))
        }
        ServiceInstallScope::System { .. } => Ok(PathBuf::from(format!(
            "/etc/systemd/system/{SERVICE_NAME}.service"
        ))),
    }
}

fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> anyhow::Result<std::process::ExitStatus> {
    let mut child = cmd.spawn()?;
    let start = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("timed out after {}s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn systemctl_user(args: &[&str]) -> anyhow::Result<()> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user").arg("--no-pager").args(args);

    let status = run_with_timeout(&mut cmd, SYSTEMCTL_TIMEOUT).map_err(|e| {
        anyhow::anyhow!(
            "systemctl --user {} failed: {e}.\n\
\n\
This usually means your user systemd manager isn't reachable over D-Bus (org.freedesktop.systemd1).\n\
If `systemctl --user` hangs outside of cratedex too, fix your session first (common fixes: log out/in, reboot, or ensure you're not in a container/SSH session without a user systemd instance).",
            args.join(" ")
        )
    })?;
    if !status.success() {
        anyhow::bail!(
            "systemctl --user {} failed (exit {})",
            args.join(" "),
            status
        );
    }
    Ok(())
}

fn systemctl_system(args: &[&str]) -> anyhow::Result<()> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--no-pager").args(args);

    let status = run_with_timeout(&mut cmd, SYSTEMCTL_TIMEOUT)
        .map_err(|e| anyhow::anyhow!("systemctl {} failed: {e}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("systemctl {} failed (exit {})", args.join(" "), status);
    }
    Ok(())
}
