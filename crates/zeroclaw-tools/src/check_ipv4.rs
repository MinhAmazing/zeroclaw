use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio::process::Command;
use zeroclaw_api::tool::{Tool, ToolResult};
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::policy::ToolOperation;

/// Checks IPv4 network information including ping reachability, local IP, and public IP.
pub struct CheckIpv4Tool {
    security: Arc<SecurityPolicy>,
}

impl CheckIpv4Tool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

/// Validate an IPv4 address string (e.g. "192.168.1.1").
fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

/// Generate a help message with usage examples for the check_ipv4 tool.
fn generate_help() -> String {
    let mut help = String::from("🔧 **Check IPv4 Tool** — Network diagnostics\n\n");
    help.push_str("⚡️ **Modes:**\n");
    help.push_str("  • `ping` — Test if an IP address is reachable (4 packets, 5s timeout)\n");
    help.push_str("  • `local` — Get the local machine's IPv4 address\n");
    help.push_str("  • `public` — Get your public IPv4 address from external service\n\n");
    help.push_str("📝 **Usage Examples:**\n");
    help.push_str("  ```json\n");
    help.push_str(r#"{"mode": "ping", "target_ip": "8.8.8.8"}"#);
    help.push_str("\n  ```\n");
    help.push_str("  ```json\n");
    help.push_str(r#"{"mode": "local"}"#);
    help.push_str("\n  ```\n");
    help.push_str("  ```json\n");
    help.push_str(r#"{"mode": "public"}"#);
    help.push_str("\n  ```\n");
    help.push_str("\n🔑 **Parameters:**\n");
    help.push_str("  • `mode` — Required: ping, local, public\n");
    help.push_str("  • `target_ip` — Target IPv4 address (required for ping mode)\n");
    help
}

#[async_trait]
impl Tool for CheckIpv4Tool {
    fn name(&self) -> &str {
        "check_ipv4"
    }

    fn description(&self) -> &str {
        "Check IPv4 network information. \
         Modes: ping (test reachability), local (get local IP), public (get public IP). \
         Use 'help' mode for full usage guide. \
         Example: /check_ipv4 {\"mode\": \"ping\", \"target_ip\": \"8.8.8.8\"}"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["help", "ping", "local", "public"],
                    "description": "Check mode: 'help' for usage guide, 'ping' to test reachability, 'local' for local IP, 'public' for public IP"
                },
                "target_ip": {
                    "type": "string",
                    "description": "Target IPv4 address to ping (required when mode is 'ping', e.g. '192.168.1.1')"
                }
            },
            "required": ["mode"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // Extract mode (required)
        let mode = args.get("mode").and_then(|v| v.as_str()).ok_or_else(|| {
            anyhow::Error::msg("Missing 'mode' parameter. Use 'help' for usage guide.")
        })?;

        // Handle help mode — no security policy needed
        if mode == "help" {
            return Ok(ToolResult {
                success: true,
                output: generate_help(),
                error: None,
            });
        }

        // Enforce act policy for actual network operations
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "check_ipv4")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        match mode {
            "ping" => execute_ping(args).await,
            "local" => execute_local_ip().await,
            "public" => execute_public_ip().await,
            _ => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Invalid mode '{}'. Use 'help' for full usage guide.",
                    mode
                )),
            }),
        }
    }
}

async fn execute_ping(args: serde_json::Value) -> anyhow::Result<ToolResult> {
    let target_ip = args
        .get("target_ip")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::Error::msg("Missing 'target_ip' parameter (required for ping mode)")
        })?;

    // Validate IPv4 format
    if !is_valid_ipv4(target_ip) {
        return Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(format!(
                "Invalid IPv4 address format: '{}'. Expected format: x.x.x.x (e.g. 192.168.1.1)",
                target_ip
            )),
        });
    }

    // Run ping command (platform-aware)
    let output = match Command::new("ping")
        .args(["-c", "4", "-W", "5", target_ip])
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to execute ping command: {}", e)),
            });
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // Parse summary line for packet loss
        let summary = stdout
            .lines()
            .rev()
            .find(|line| line.contains("packet loss"))
            .unwrap_or("");

        Ok(ToolResult {
            success: true,
            output: format!(
                "Ping to {} successful.\n{}\n{}",
                target_ip,
                stdout.trim(),
                summary
            ),
            error: None,
        })
    } else {
        Ok(ToolResult {
            success: false,
            output: stdout.trim().to_string(),
            error: Some(format!(
                "Ping to {} failed (exit code {}). {}",
                target_ip,
                output
                    .status
                    .code()
                    .map_or("unknown".to_string(), |c| c.to_string()),
                stderr.trim()
            )),
        })
    }
}

async fn execute_local_ip() -> anyhow::Result<ToolResult> {
    // Try multiple methods to get local IPv4
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("ipconfig")
            .args(["getifaddr", "en0"])
            .output()
            .await
            && output.status.success()
        {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip.is_empty() && is_valid_ipv4(&ip) {
                return Ok(ToolResult {
                    success: true,
                    output: format!("Local IPv4 address (en0): {}", ip),
                    error: None,
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("hostname").arg("-I").output().await
            && output.status.success()
        {
            let ips = String::from_utf8_lossy(&output.stdout);
            // Return first IPv4 address
            for ip in ips.trim().split_whitespace() {
                if is_valid_ipv4(ip) {
                    return Ok(ToolResult {
                        success: true,
                        output: format!("Local IPv4 address: {}", ip),
                        error: None,
                    });
                }
            }
        }
    }

    // Fallback: try `ip route` on Linux or `ifconfig` on macOS
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("ip")
            .args(["-4", "addr", "show"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("inet ") {
                    let ip: String = line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    if is_valid_ipv4(&ip) {
                        return Ok(ToolResult {
                            success: true,
                            output: format!("Local IPv4 address: {}", ip),
                            error: None,
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("ifconfig").arg("en0").output().await {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("inet ") {
                    let ip: String = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    if is_valid_ipv4(&ip) {
                        return Ok(ToolResult {
                            success: true,
                            output: format!("Local IPv4 address (en0): {}", ip),
                            error: None,
                        });
                    }
                }
            }
        }
    }

    Ok(ToolResult {
        success: false,
        output: String::new(),
        error: Some("Could not determine local IPv4 address".to_string()),
    })
}

async fn execute_public_ip() -> anyhow::Result<ToolResult> {
    // Try multiple public IP services as fallback
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://icanhazip.com",
    ];

    for service in &services {
        match Command::new("curl")
            .args(["-s", "-m", "10", "--fail", service])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() && is_valid_ipv4(&ip) {
                    return Ok(ToolResult {
                        success: true,
                        output: format!("Public IPv4 address: {} (via {})", ip, service),
                        error: None,
                    });
                }
            }
            _ => continue,
        }
    }

    Ok(ToolResult {
        success: false,
        output: String::new(),
        error: Some("Could not determine public IPv4 address. All services failed.".to_string()),
    })
}
