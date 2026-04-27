use tokio::process::Command;

use crate::utils::command_path::resolve_command_path;

pub(crate) async fn flush_conntrack_table() -> Result<(), String> {
    flush_conntrack_target(&["-F"]).await
}

pub(crate) async fn flush_conntrack_expect() -> Result<(), String> {
    flush_conntrack_target(&["-F", "expect"]).await
}

async fn flush_conntrack_target(args: &[&str]) -> Result<(), String> {
    if resolve_command_path("conntrack").is_none() {
        return Ok(());
    }

    let out = Command::new("conntrack")
        .args(args)
        .output()
        .await
        .map_err(|err| err.to_string())?;

    if out.status.success() {
        return Ok(());
    }

    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if err.is_empty() {
        Err("failed".to_string())
    } else {
        Err(err)
    }
}
