use super::{SERVICE_NAME, ServiceConfig, ServiceInstallScope, ServiceManager, require_root};
use std::path::PathBuf;
use std::process::Command;

const LABEL: &str = "com.cratedex.server";

pub struct MacosServiceManager;

impl ServiceManager for MacosServiceManager {
    fn install(&self, config: &ServiceConfig) -> anyhow::Result<()> {
        let plist_path = plist_path(&config.scope)?;

        if let ServiceInstallScope::System { .. } = &config.scope {
            require_root(
                "install-service --system",
                &config.exec_path.to_string_lossy(),
            )?;
        }

        let content = plist_content(config);
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&plist_path, content)?;
        eprintln!("Wrote {}", plist_path.display());

        let path = plist_path.to_string_lossy().to_string();
        let _ = run_launchctl(&["unload", "-w", &path]);
        run_launchctl(&["load", "-w", &path])?;

        match &config.scope {
            ServiceInstallScope::CurrentUser => {
                eprintln!("Service {SERVICE_NAME} loaded via launchd for current user.");
            }
            ServiceInstallScope::System { run_as } => {
                eprintln!("System launchd service {SERVICE_NAME} loaded (UserName={run_as}).");
            }
        }
        Ok(())
    }

    fn remove(&self, scope: ServiceInstallScope) -> anyhow::Result<()> {
        let plist_path = plist_path(&scope)?;

        if let ServiceInstallScope::System { .. } = &scope {
            require_root("remove-service --system", "cratedex")?;
        }

        let path = plist_path.to_string_lossy().to_string();
        let _ = run_launchctl(&["unload", "-w", &path]);

        if plist_path.exists() {
            std::fs::remove_file(&plist_path)?;
            eprintln!("Removed {}", plist_path.display());
        } else {
            eprintln!("Service file not found at {}", plist_path.display());
        }

        Ok(())
    }
}

fn plist_path(scope: &ServiceInstallScope) -> anyhow::Result<PathBuf> {
    match scope {
        ServiceInstallScope::CurrentUser => {
            let home =
                dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
            Ok(home
                .join("Library")
                .join("LaunchAgents")
                .join(format!("{LABEL}.plist")))
        }
        ServiceInstallScope::System { .. } => Ok(PathBuf::from(format!(
            "/Library/LaunchDaemons/{LABEL}.plist"
        ))),
    }
}

fn plist_content(config: &ServiceConfig) -> String {
    let exec_path = xml_escape(&config.exec_path.to_string_lossy());
    let host = xml_escape(&config.host);
    let port = config.port;
    let allow_remote = config.allow_remote;

    let user_name_section = match &config.scope {
        ServiceInstallScope::System { run_as } => {
            format!(
                "\n    <key>UserName</key>\n    <string>{}</string>",
                xml_escape(run_as)
            )
        }
        ServiceInstallScope::CurrentUser => String::new(),
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LABEL}</string>
    <key>ProgramArguments</key><array>
        <string>{exec_path}</string>
        <string>server</string>
    </array>
    <key>EnvironmentVariables</key><dict>
        <key>CRATEDEX__SERVER__TRANSPORT</key><string>http</string>
        <key>CRATEDEX__SERVER__HOST</key><string>{host}</string>
        <key>CRATEDEX__SERVER__PORT</key><string>{port}</string>
        <key>CRATEDEX__SERVER__ALLOW_REMOTE</key><string>{allow_remote}</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>{user_name_section}
</dict>
</plist>
"#
    )
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn run_launchctl(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("launchctl").args(args).status()?;
    if !status.success() {
        anyhow::bail!("launchctl {} failed (exit {})", args.join(" "), status);
    }
    Ok(())
}
