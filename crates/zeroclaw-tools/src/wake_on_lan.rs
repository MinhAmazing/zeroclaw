use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio::process::Command;
use zeroclaw_api::tool::{Tool, ToolResult};
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::policy::ToolOperation;

/// Sends a Wake-on-LAN magic packet to power on a device by MAC address.
///
/// Uses the `wakeonlan` command-line tool to send the magic packet.
pub struct WakeOnLanTool {
    security: Arc<SecurityPolicy>,
}

impl WakeOnLanTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

/// Validate a MAC address string (accepts common formats: AA:BB:CC:DD:EE:FF,
/// AA-BB-CC-DD-EE-FF, AABCCDDEEFF).
fn is_valid_mac_address(mac: &str) -> bool {
    let cleaned = mac.replace([':', '-'], "");
    if cleaned.len() != 12 {
        return false;
    }
    cleaned.chars().all(|c| c.is_ascii_hexdigit())
}

/// Generate a help message with usage examples for the wake_on_lan tool.
fn generate_help() -> String {
    let mut help = String::from("🔧 **Wake-on-LAN Tool** — Power on devices via network\n\n");
    help.push_str("⚡️ **What it does:**\n");
    help.push_str("  Sends a Wake-on-LAN magic packet to wake up a sleeping/off device on your local network.\n\n");
    help.push_str("📝 **Usage Example:**\n");
    help.push_str("  ```json\n");
    help.push_str(r#"{"mac_address": "AA:BB:CC:DD:EE:FF"}"#);
    help.push_str("\n  ```\n");
    help.push_str("\n🔑 **Parameters:**\n");
    help.push_str("  • `mac_address` — MAC address of the target device\n");
    help.push_str("    Formats: AA:BB:CC:DD:EE:FF | AA-BB-CC-DD-EE-FF | AABCCDDEEFF\n\n");
    help.push_str("⚠️ **Requirements:**\n");
    help.push_str("  • Target device must have WoL enabled in BIOS/UEFI\n");
    help.push_str("  • Target device must be on the same local network\n");
    help.push_str("  • `wakeonlan` CLI tool must be installed on this machine\n");
    help
}

#[async_trait]
impl Tool for WakeOnLanTool {
    fn name(&self) -> &str {
        "wake_on_lan"
    }

    fn description(&self) -> &str {
        "Send a Wake-on-LAN magic packet to power on a device by its MAC address. \
         Use 'help' for usage guide. \
         Example: /wake_on_lan {\"mac_address\": \"AA:BB:CC:DD:EE:FF\"}"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "mac_address": {
                    "type": "string",
                    "description": "MAC address of the device to wake (e.g. 'AA:BB:CC:DD:EE:FF'). Use 'help' instead for usage guide."
                }
            },
            "required": ["mac_address"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // Extract mac_address (may be "help")
        let mac_address = args
            .get("mac_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::Error::msg("Missing 'mac_address' parameter. Use 'help' for usage guide.")
            })?;

        // Handle help action — no security policy needed
        if mac_address == "help" {
            return Ok(ToolResult {
                success: true,
                output: generate_help(),
                error: None,
            });
        }

        // Enforce act policy for actual WoL actions
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "wake_on_lan")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        // Validate MAC address format
        if !is_valid_mac_address(mac_address) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Invalid MAC address format: '{}'. Expected format: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, or AABCCDDEEFF",
                    mac_address
                )),
            });
        }

        // Execute wakeonlan command
        let output = match Command::new("wakeonlan").arg(mac_address).output().await {
            Ok(output) => output,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Failed to execute wakeonlan command: {}. Ensure `wakeonlan` is installed on the system.",
                        e
                    )),
                });
            }
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            let mut result_msg = format!("Wake-on-LAN magic packet sent to {}.", mac_address);
            if !stdout.trim().is_empty() {
                result_msg.push_str(&format!("\nOutput: {}", stdout.trim()));
            }
            if !stderr.trim().is_empty() {
                result_msg.push_str(&format!("\nWarning: {}", stderr.trim()));
            }

            Ok(ToolResult {
                success: true,
                output: result_msg,
                error: None,
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            Ok(ToolResult {
                success: false,
                output: stdout.trim().to_string(),
                error: Some(format!(
                    "wakeonlan command failed with exit code {}.\n{}",
                    output
                        .status
                        .code()
                        .map_or("unknown".to_string(), |c| c.to_string()),
                    stderr.trim()
                )),
            })
        }
    }
}
