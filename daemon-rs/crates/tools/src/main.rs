use std::{
    collections::hash_map::DefaultHasher,
    env, fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    process::Command,
};

type DynError = Box<dyn std::error::Error>;

const TABLE_HEADER: &str = "| Date | Backend | Profile | Rounds | Commit | p50 ms | p95 ms | p99 ms | max ms | drop_total | Baseline Check | Go Ref | vs Go p50 | vs Go p95 | vs Go p99 | vs Go max | vs Go drop | Prev Commit Ref | vs Prev p50 | vs Prev p95 | vs Prev p99 | vs Prev max | vs Prev drop | Notes |";
const EMPTY_COMPARISON_COLUMNS: &str = "- | - | - | - | - | - | - | - | - | - | - | -";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DynError> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("update-run-perf") => update_perf_md(),
        Some(command) => Err(format!("unsupported tools command: {command}").into()),
        None => Err("usage: cargo run -p tools -- update-run-perf".into()),
    }
}

fn update_perf_md() -> Result<(), DynError> {
    let tools_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let daemon_rs_dir = tools_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("tools dir missing daemon-rs parent")?;
    let repo_root = daemon_rs_dir.parent().ok_or("daemon-rs dir missing parent")?;
    let perf_md = env::var("PERF_MD_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| daemon_rs_dir.join("PERF.md"));
    let stress_rounds = env::var("STRESS_ROUNDS").unwrap_or_else(|_| "2000".to_string());
    let run_date = run_git(daemon_rs_dir, ["log", "-1", "--date=short", "--pretty=%ad"]); 
    let current_commit = run_git(daemon_rs_dir, ["rev-parse", "--short", "HEAD"]);
    let current_subject = run_git(daemon_rs_dir, ["log", "-1", "--pretty=%s"]);
    let prev_commit = run_git(daemon_rs_dir, ["rev-parse", "--short", "HEAD^"]);
    let prev_commit_full = run_git(daemon_rs_dir, ["rev-parse", "HEAD^"]);
    let prev_subject = run_git(daemon_rs_dir, ["log", "-1", "--pretty=%s", "HEAD^"]);
    let cache_root = cache_root(repo_root);
    let refresh_prev_base = env_flag("OPENSNITCH_PERF_REFRESH_BASE");
    let workspace_state = if run_git(repo_root, ["status", "--short"]).is_empty() {
        "clean"
    } else {
        "dirty"
    };

    println!("Running current Rust release stress profile...");
    let current_rust_output = run_command(
        repo_root,
        "cargo",
        [
            "test",
            "--manifest-path",
            daemon_rs_dir.join("Cargo.toml").to_string_lossy().as_ref(),
            "--release",
            "-p",
            "opensnitchd-rs",
            "stress_profile_reports_connect_latency_and_pipeline_drops",
            "--",
            "--ignored",
            "--nocapture",
        ],
        &[("OPENSNITCH_STRESS_ROUNDS", stress_rounds.as_str())],
    )?;
    let current_rust_line = find_line(&current_rust_output, "stress-profile rounds=")?;

    println!("Running current Go stress profile...");
    let current_go_output = run_command(
        &repo_root.join("daemon"),
        "go",
        [
            "test",
            "./runtimeprofile",
            "-run",
            "TestStressProfileReportsConnectLatencyAndPipelineDrops",
            "-count=1",
            "-v",
        ],
        &[
            ("OPENSNITCH_STRESS_PROFILE", "1"),
            ("OPENSNITCH_STRESS_ROUNDS", stress_rounds.as_str()),
        ],
    )?;
    let current_go_line = find_line(&current_go_output, "stress-profile backend=go")?;

    let prev_rust_line = cached_or_run_prev_rust_profile(
        repo_root,
        &cache_root,
        &prev_commit,
        &prev_commit_full,
        &stress_rounds,
        refresh_prev_base,
    )?;

    let current_rust = Metrics::parse(current_rust_line)?;
    let current_go = Metrics::parse(current_go_line)?;
    let prev_rust = Metrics::parse(&prev_rust_line)?;

    let row_rust = format!(
        "| {run_date} | Rust | release (ThinLTO) | {stress_rounds} | `{current_commit}` | {current_rust} | pass | Go default same run | {vs_go} | `{prev_commit}` | {vs_prev} | Auto-updated current reference Rust run ({current_subject}); workspace {workspace_state}. |",
        current_rust = current_rust.format_values(),
        vs_go = current_rust.delta_string(&current_go),
        vs_prev = current_rust.delta_string(&prev_rust),
    );
    let row_go = format!(
        "| {run_date} | Go | default | {stress_rounds} | `{current_commit}` | {current_go} | pass | {empty} | Auto-updated current Go comparison row paired with Rust actual. |",
        current_go = current_go.format_values(),
        empty = EMPTY_COMPARISON_COLUMNS,
    );
    let row_prev = format!(
        "| {run_date} | Rust | release (ThinLTO) | {stress_rounds} | `{prev_commit}` | {prev_rust} | pass | {empty} | Auto-updated previous commit benchmark ({prev_subject}) using cached previous-commit worktree/results when available. |",
        prev_rust = prev_rust.format_values(),
        empty = EMPTY_COMPARISON_COLUMNS,
    );

    prepend_rows(&perf_md, &[row_rust, row_go, row_prev])?;

    println!("Updated {}", perf_md.display());
    println!("Current Rust: {current_rust_line}");
    println!("Current Go:   {current_go_line}");
    println!("Prev Rust:    {prev_rust_line}");
    println!("Prev cache:   {}", cache_root.display());

    Ok(())
}

fn cached_or_run_prev_rust_profile(
    repo_root: &Path,
    cache_root: &Path,
    prev_commit: &str,
    prev_commit_full: &str,
    stress_rounds: &str,
    refresh_prev_base: bool,
) -> Result<String, DynError> {
    fs::create_dir_all(cache_root)?;
    let cached_result_path = cache_root.join(format!(
        "prev-rust-release-{prev_commit}-rounds-{stress_rounds}.txt"
    ));

    if !refresh_prev_base && cached_result_path.is_file() {
        let cached_line = fs::read_to_string(&cached_result_path)?.trim().to_string();
        if cached_line.contains("stress-profile rounds=") {
            println!(
                "Reusing cached previous-commit Rust profile from {}",
                cached_result_path.display()
            );
            return Ok(cached_line);
        }
    }

    let worktree_path = cache_root.join("prev-worktree");
    ensure_cached_worktree(repo_root, &worktree_path, prev_commit_full)?;

    println!("Running previous-commit Rust release stress profile...");
    let prev_rust_output = run_command(
        repo_root,
        "cargo",
        [
            "test",
            "--manifest-path",
            worktree_path.join("daemon-rs/Cargo.toml").to_string_lossy().as_ref(),
            "--release",
            "-p",
            "opensnitchd-rs",
            "stress_profile_reports_connect_latency_and_pipeline_drops",
            "--",
            "--ignored",
            "--nocapture",
        ],
        &[("OPENSNITCH_STRESS_ROUNDS", stress_rounds)],
    )?;
    let prev_rust_line = find_line(&prev_rust_output, "stress-profile rounds=")?.to_string();
    fs::write(&cached_result_path, format!("{prev_rust_line}\n"))?;
    Ok(prev_rust_line)
}

fn ensure_cached_worktree(
    repo_root: &Path,
    worktree_path: &Path,
    expected_commit: &str,
) -> Result<(), DynError> {
    if worktree_path.exists() {
        let current_head = run_command(
            worktree_path,
            "git",
            ["rev-parse", "HEAD"],
            &[],
        )
        .ok()
        .map(|value| value.trim().to_string());
        if current_head.as_deref() == Some(expected_commit) {
            return Ok(());
        }

        let _ = run_command(
            repo_root,
            "git",
            ["worktree", "remove", worktree_path.to_string_lossy().as_ref(), "--force"],
            &[],
        );
        if worktree_path.exists() {
            fs::remove_dir_all(worktree_path)?;
        }
    }

    run_command(
        repo_root,
        "git",
        [
            "worktree",
            "add",
            "--detach",
            worktree_path.to_string_lossy().as_ref(),
            expected_commit,
        ],
        &[],
    )?;
    Ok(())
}

fn prepend_rows(perf_md: &Path, rows: &[String]) -> Result<(), DynError> {
    let text = fs::read_to_string(perf_md)?;
    let header_idx = text.find(TABLE_HEADER).ok_or("run history table header not found in PERF.md")?;
    let first_newline = text[header_idx..].find('\n').ok_or("run history header line not terminated")? + header_idx;
    let second_newline = text[first_newline + 1..].find('\n').ok_or("run history divider row not found")? + first_newline + 1;
    let insert_at = second_newline + 1;
    let mut updated = String::with_capacity(text.len() + rows.len() * 256);
    updated.push_str(&text[..insert_at]);
    for row in rows {
        updated.push_str(row);
        updated.push('\n');
    }
    updated.push_str(&text[insert_at..]);
    fs::write(perf_md, updated)?;
    Ok(())
}

fn run_git<const N: usize>(cwd: &Path, args: [&str; N]) -> String {
    run_command(cwd, "git", args, &[]).expect("git command failed").trim().to_string()
}

fn run_command<const N: usize>(cwd: &Path, program: &str, args: [&str; N], envs: &[(&str, &str)]) -> Result<String, DynError> {
    let mut command = Command::new(program);
    command.current_dir(cwd).args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "command failed: {} {}\nstdout:\n{}\nstderr:\n{}",
            program,
            args.join(" "),
            stdout,
            stderr
        )
        .into())
    }
}

fn find_line<'a>(text: &'a str, needle: &str) -> Result<&'a str, DynError> {
    text.lines()
        .find(|line| line.contains(needle))
        .ok_or_else(|| format!("expected output line containing: {needle}").into())
}

fn cache_root(repo_root: &Path) -> PathBuf {
    if let Ok(value) = env::var("OPENSNITCH_PERF_CACHE_DIR") {
        return PathBuf::from(value);
    }

    let mut hasher = DefaultHasher::new();
    repo_root.to_string_lossy().hash(&mut hasher);
    let repo_hash = hasher.finish();
    env::temp_dir().join(format!("opensnitch-perf-cache-{repo_hash:016x}"))
}

fn env_flag(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES"))
}

#[derive(Clone, Copy)]
struct Metrics {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
    drop_total: f64,
}

impl Metrics {
    fn parse(line: &str) -> Result<Self, DynError> {
        Ok(Self {
            p50: parse_metric(line, "p50_ms")?,
            p95: parse_metric(line, "p95_ms")?,
            p99: parse_metric(line, "p99_ms")?,
            max: parse_metric(line, "max_ms")?,
            drop_total: parse_metric(line, "drop_total")?,
        })
    }

    fn format_values(self) -> String {
        format!(
            "{:.3} | {:.3} | {:.3} | {:.3} | {:.0}",
            self.p50, self.p95, self.p99, self.max, self.drop_total
        )
    }

    fn delta_string(self, base: &Self) -> String {
        format!(
            "{:+.3} | {:+.3} | {:+.3} | {:+.3} | {:+.0}",
            self.p50 - base.p50,
            self.p95 - base.p95,
            self.p99 - base.p99,
            self.max - base.max,
            self.drop_total - base.drop_total,
        )
    }
}

fn parse_metric(line: &str, key: &str) -> Result<f64, DynError> {
    let prefix = format!("{key}=");
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing metric {key} in line: {line}"))?;
    Ok(value.parse::<f64>()?)
}