use anyhow::{Context as _, Result, bail};

/// Run `bin` with `args`, wait for it, and `bail!` with `stderr` on non-zero exit.
/// `context` is used both as the `.with_context` message and the failure prefix.
pub(crate) async fn run_command_checked(bin: &str, args: &[&str], context: &str) -> Result<()> {
    let out = tokio::process::Command::new(bin)
        .args(args)
        .output()
        .await
        .with_context(|| format!("{context}: spawn failed"))?;

    if !out.status.success() {
        bail!(
            "{context} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    Ok(())
}
