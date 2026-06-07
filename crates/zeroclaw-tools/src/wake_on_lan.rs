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

#[async_trait]
impl Tool for WakeOnLanTool {
    fn name(&self) -> &str {
        "wake_on_lan"
    }

    fn description(&self) -> &str {
        "Send a Wake-on-LAN magic packet to power on a device by its MAC address. \
         The target device must have WoL enabled in its BIOS/UEFI and network settings. \
         Requires the `wakeonlan` command-line tool to be installed on the system."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "mac_address": {
                    "type": "string",
                    "description": "MAC address of the device to wake (e.g. 'AA:BB:CC:DD:EE:FF', 'AA-BB-CC-DD-EE-FF', or 'AABCCDDEEFF')"
                }
            },
            "required": ["mac_address"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // Enforce act policy
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

        // Extract MAC address (required)
        let mac_address = args.get("mac_address").and_then(|v| v.as_str()).ok_or_else(|| {
            anyhow::Error::msg("Missing 'mac_address' parameter")
        })?;

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
        let output = match Command::new("wakeonlan")
            .arg(mac_address)
            .output()
            .await
        {
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
                    output.status.code().map_or("unknown".to_string(), |c| c.to_string()),
                    stderr.trim()
                )),
            })
        }
    }
}
