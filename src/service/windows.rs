use super::{SERVICE_NAME, ServiceConfig, ServiceInstallScope, ServiceManager};
use std::path::PathBuf;
use std::process::Command;

const TASK_NAME: &str = "Cratedex";

pub struct WindowsServiceManager;

impl ServiceManager for WindowsServiceManager {
    fn install(&self, config: &ServiceConfig) -> anyhow::Result<()> {
        if matches!(config.scope, ServiceInstallScope::System { .. }) {
            anyhow::bail!(
                "System-level service install on Windows is not implemented. \
Use NSSM (https://nssm.cc/) to run cratedex as a Windows Service."
            );
        }

        let script = task_script_path()?;
        if let Some(parent) = script.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&script, task_script_content(config))?;

        let task_command = format!("\"{}\"", script.display());
        let status = Command::new("schtasks")
            .args([
                "/create",
                "/tn",
                TASK_NAME,
                "/tr",
                &task_command,
                "/sc",
                "onlogon",
                "/rl",
                "limited",
                "/f",
            ])
            .status()?;

        if !status.success() {
            anyhow::bail!("schtasks /create failed (exit {status})");
        }

        eprintln!("Task Scheduler entry {TASK_NAME} created for {SERVICE_NAME}.");
        Ok(())
    }

    fn remove(&self, scope: ServiceInstallScope) -> anyhow::Result<()> {
        if matches!(scope, ServiceInstallScope::System { .. }) {
            anyhow::bail!(
                "System-level service removal on Windows is not implemented by cratedex."
            );
        }

        let _ = Command::new("schtasks")
            .args(["/delete", "/tn", TASK_NAME, "/f"])
            .status();

        let script = task_script_path()?;
        if script.exists() {
            std::fs::remove_file(&script)?;
        }

        eprintln!("Task Scheduler entry {TASK_NAME} removed.");
        Ok(())
    }
}

fn task_script_path() -> anyhow::Result<PathBuf> {
    if let Ok(app_data) = std::env::var("APPDATA")
        && !app_data.trim().is_empty()
    {
        return Ok(PathBuf::from(app_data)
            .join("cratedex")
            .join("run-cratedex.cmd"));
    }

    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not resolve home directory"))?;
    Ok(home
        .join("AppData")
        .join("Roaming")
        .join("cratedex")
        .join("run-cratedex.cmd"))
}

fn task_script_content(config: &ServiceConfig) -> String {
    let exe = config.exec_path.display();
    format!(
        "@echo off\r\n\
         set CRATEDEX__SERVER__TRANSPORT=http\r\n\
         set CRATEDEX__SERVER__HOST={}\r\n\
         set CRATEDEX__SERVER__PORT={}\r\n\
         set CRATEDEX__SERVER__ALLOW_REMOTE={}\r\n\
         \"{}\" server\r\n",
        config.host, config.port, config.allow_remote, exe
    )
}
