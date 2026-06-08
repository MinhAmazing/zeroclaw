use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio::process::Command;
use zeroclaw_api::tool::{Tool, ToolResult};
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::policy::ToolOperation;

/// Controls a remote machine via SSH (shutdown, restart, run arbitrary commands).
///
/// Uses the `ssh` command-line tool with key-based authentication.
pub struct SshControlTool {
    security: Arc<SecurityPolicy>,
}

impl SshControlTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

/// Map of preset actions to their corresponding remote commands.
const PRESET_ACTIONS: &[(&str, &str)] = &[
    ("shutdown", "shutdown /s /t 0"),
    ("restart", "shutdown /r /t 0"),
    ("lock", "rundll32.exe user32.dll,LockWorkStation"),
    ("sleep", "rundll32.exe powrprof.dll,SetSuspendState 0,1,0"),
    ("hibernate", "shutdown /h"),
    ("logoff", "shutdown /l"),
];

/// Resolve a preset action name to its remote command, or return None for custom commands.
fn resolve_action(action: &str) -> Option<&'static str> {
    PRESET_ACTIONS
        .iter()
        .find(|(name, _)| *name == action)
        .map(|(_, cmd)| *cmd)
}

/// Generate a help message with usage examples for the ssh_control tool.
fn generate_help() -> String {
    let mut help = String::from("🔧 **SSH Control Tool** — Remote machine control via SSH\n\n");
    help.push_str("⚡️ **Preset Actions:**\n");
    for (name, cmd) in PRESET_ACTIONS {
        help.push_str(&format!("  • `{name}` — {cmd}\n"));
    }
    help.push_str("\n📝 **Usage Examples:**\n");
    help.push_str("  ```json\n");
    help.push_str(r#"{"action": "shutdown", "host": "192.168.2.168", "user": "hello"}"#);
    help.push_str("\n  ```\n");
    help.push_str("  ```json\n");
    help.push_str(r#"{"action": "custom", "host": "192.168.2.168", "user": "hello", "command": "ipconfig"}"#);
    help.push_str("\n  ```\n");
    help.push_str("\n🔑 **Parameters:**\n");
    help.push_str("  • `action` — Required: help, shutdown, restart, lock, sleep, hibernate, logoff, custom\n");
    help.push_str("  • `host` — Remote IP or hostname (required for non-help actions)\n");
    help.push_str("  • `user` — SSH username (required for non-help actions)\n");
    help.push_str("  • `command` — Custom command (required if action is 'custom')\n");
    help.push_str("  • `key_path` — SSH key path (default: ~/.ssh/id_ed25519)\n");
    help
}

#[async_trait]
impl Tool for SshControlTool {
    fn name(&self) -> &str {
        "ssh_control"
    }

    fn description(&self) -> &str {
        "Control a remote Windows machine via SSH. \
         Actions: shutdown, restart, lock, sleep, hibernate, logoff, custom. \
         Use 'help' action for full usage guide. \
         Example: /ssh_control {\"host\":\"192.168.2.168\",\"user\":\"hello\",\"action\":\"shutdown\"}"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Remote host IP or hostname (e.g. '192.168.2.168')"
                },
                "user": {
                    "type": "string",
                    "description": "SSH username (e.g. 'hello')"
                },
                "action": {
                    "type": "string",
                    "enum": ["help", "shutdown", "restart", "lock", "sleep", "hibernate", "logoff", "custom"],
                    "description": "Action to perform. Use 'help' for full usage guide and examples."
                },
                "command": {
                    "type": "string",
                    "description": "Custom command to run (required if action is 'custom')"
                },
                "key_path": {
                    "type": "string",
                    "description": "Path to SSH private key (default: ~/.ssh/id_ed25519)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // Extract action (always required)
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::Error::msg("Missing 'action' parameter"))?;

        // Handle help action — no SSH connection or security policy needed
        if action == "help" {
            return Ok(ToolResult {
                success: true,
                output: generate_help(),
                error: None,
            });
        }

        // Enforce act policy for non-help actions
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "ssh_control")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        // Extract required parameters (host and user needed for actual actions)
        let host = args
            .get("host")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::Error::msg("Missing 'host' parameter. Use action 'help' for usage guide.")
            })?;

        let user = args
            .get("user")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::Error::msg("Missing 'user' parameter. Use action 'help' for usage guide.")
            })?;

        let key_path = args
            .get("key_path")
            .and_then(|v| v.as_str())
            .unwrap_or("~/.ssh/id_ed25519");

        // Resolve the remote command based on action
        let remote_command = if action == "custom" {
            args.get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::Error::msg("Missing 'command' parameter for custom action"))?
                .to_string()
        } else {
            resolve_action(action).ok_or_else(|| {
                anyhow::Error::msg(format!(
                    "Unknown action '{}'. Use action 'help' for full usage guide.",
                    action
                ))
            })?.to_string()
        };

        let target = format!("{}@{}", user, host);

        // Execute SSH command
        let output = Command::new("ssh")
            .args([
                "-i",
                key_path,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                &target,
                &remote_command,
            ])
            .output()
            .await;

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                if output.status.success() {
                    Ok(ToolResult {
                        success: true,
                        output: format!(
                            "Successfully executed '{}' on {}.\n{}",
                            action,
                            target,
                            stdout.trim()
                        ),
                        error: None,
                    })
                } else {
                    Ok(ToolResult {
                        success: false,
                        output: stdout.trim().to_string(),
                        error: Some(format!(
                            "SSH command failed (exit code {}). {}",
                            output
                                .status
                                .code()
                                .map_or("unknown".to_string(), |c| c.to_string()),
                            stderr.trim()
                        )),
                    })
                }
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Failed to execute SSH command: {}", e)),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_action_returns_known_commands() {
        assert_eq!(resolve_action("shutdown"), Some("shutdown /s /t 0"));
        assert_eq!(resolve_action("restart"), Some("shutdown /r /t 0"));
        assert_eq!(
            resolve_action("lock"),
            Some("rundll32.exe user32.dll,LockWorkStation")
        );
        assert_eq!(
            resolve_action("sleep"),
            Some("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
        );
        assert_eq!(resolve_action("hibernate"), Some("shutdown /h"));
        assert_eq!(resolve_action("logoff"), Some("shutdown /l"));
    }

    #[test]
    fn test_resolve_action_returns_none_for_unknown() {
        assert_eq!(resolve_action("unknown_action"), None);
        assert_eq!(resolve_action("custom"), None);
        assert_eq!(resolve_action("help"), None);
    }

    #[test]
    fn test_generate_help_contains_usage_info() {
        let help = generate_help();
        assert!(help.contains("SSH Control Tool"));
        assert!(help.contains("Preset Actions"));
        assert!(help.contains("shutdown"));
        assert!(help.contains("restart"));
        assert!(help.contains("Usage Examples"));
        assert!(help.contains("192.168.2.168"));
    }
}
