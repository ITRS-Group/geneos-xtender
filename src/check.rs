use crate::range::{Range, Ranges, RangesExt};
use crate::result::{CheckResult, CheckResultBuilder, CheckResults};
use crate::variable::{VariableError, VariableString, Variables};
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use shellwords;
use std::fmt;
use std::io::{self, Read};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

/// Plugin output beyond this many bytes is read and discarded, so a plugin that floods
/// stdout cannot exhaust memory.
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Kill the plugin and every process it started, and reap the plugin. The plugin leads its
/// own process group, so its pid is the group id.
fn kill_process_group(child: &mut Child) -> io::Result<()> {
    #[cfg(unix)]
    {
        let pgid = child.id() as libc::pid_t;
        // One killpg can miss processes while the group is being torn down (seen on macOS
        // when several checks time out at once), so repeat it until the group is empty.
        // The plugin is reaped in between, since a zombie still counts as a member.
        for attempt in 0..50 {
            // SAFETY: killpg only sends a signal; it takes no pointers.
            if unsafe { libc::killpg(pgid, libc::SIGKILL) } != 0 {
                let e = io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(libc::ESRCH) => Ok(()),
                    _ if attempt == 0 => child.kill(),
                    _ => Err(e),
                };
            }
            let _ = child.try_wait();
            thread::sleep(Duration::from_millis(10));
        }
        debug!("Process group {} still has members after the kill", pgid);
        Ok(())
    }
    #[cfg(not(unix))]
    child.kill()
}

/// Read `reader` to the end, keeping the first `limit` bytes in `captured`. Returns whether
/// anything was discarded.
fn read_capped(
    reader: &mut impl Read,
    captured: &Mutex<Vec<u8>>,
    limit: usize,
) -> io::Result<bool> {
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => return Ok(truncated),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let mut buffer = captured.lock().unwrap_or_else(|e| e.into_inner());
        let room = limit.saturating_sub(buffer.len());
        buffer.extend_from_slice(&chunk[..n.min(room)]);
        truncated |= n > room;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Check {
    name: String,
    command: String,
    #[serde(skip)]
    secret_command: Option<String>,
    timeout: u64,
    #[serde(skip)]
    variables_found: Option<Variables>,
    #[serde(skip)]
    variables_not_found: Option<Variables>,
}

#[derive(Debug)]
pub struct CheckBuilder {
    name: Option<String>,
    command: Option<String>,
    secret_command: Option<String>,
    timeout: Option<u64>,
    variables_found: Option<Variables>,
    variables_not_found: Option<Variables>,
}

pub type Checks = Vec<Check>;

pub trait ChecksExt {
    fn total_time_from_timeouts(&self) -> Duration;
}

enum TimeoutMessage {
    Single,
    Multi(u64),
}

impl fmt::Display for TimeoutMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutMessage::Single => write!(f, "UNKNOWN: Timed out after 1 second"),
            TimeoutMessage::Multi(timeout) => {
                write!(f, "UNKNOWN: Timed out after {} seconds", timeout)
            }
        }
    }
}

impl Default for Check {
    fn default() -> Self {
        Self {
            name: String::new(),
            command: String::new(),
            secret_command: None,
            timeout: 5,
            variables_found: None,
            variables_not_found: None,
        }
    }
}

impl Check {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The command with encrypted variables obfuscated, safe to show or write out.
    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn timeout(&self) -> u64 {
        self.timeout
    }

    pub fn secret_command(&self) -> Option<String> {
        self.secret_command.clone()
    }

    pub fn new(name: &str, command: &str, secret_command: Option<String>, timeout: u64) -> Self {
        Self {
            name: name.to_string(),
            command: command.to_string(),
            secret_command,
            timeout,
            variables_found: None,
            variables_not_found: None,
        }
    }

    pub fn secret_command_or_command(&self) -> &str {
        match &self.secret_command {
            Some(secret_command) => {
                debug!("Encrypted variable found, populating \"secret_command\".");
                secret_command
            }
            None => &self.command,
        }
    }

    // Mismatched or unsupported ranges panic: they are template authoring errors, and expanding
    // them anyway would emit checks with unresolved !!A:x..y!! tokens.
    pub fn expand_ranges(self) -> Checks {
        let mut checks = Checks::new();

        let mut name_ranges = Ranges::from_str(&self.name);
        name_ranges.sort();
        name_ranges.dedup();

        let mut command_ranges = Ranges::from_str(&self.command);
        command_ranges.sort();
        command_ranges.dedup();

        if name_ranges != command_ranges {
            panic!(
                "Ranges in name and command do not match: {:?} != {:?}",
                name_ranges, command_ranges
            );
        }

        let ranges = name_ranges;

        if ranges.is_empty() {
            checks.push(self);
            return checks;
        }

        if ranges.len() == 1 {
            return expand_checks_from_single_range(&self, &ranges[0]);
        }

        if ranges.len() == 2 {
            return expand_checks_from_double_range(&self, &ranges[0], &ranges[1]);
        }

        panic!("Only 1 or 2 ranges are supported");
    }

    pub fn run(&self) -> CheckResult {
        let safe_data = CheckResultBuilder::new()
            .name(&self.name)
            .command(&self.command)
            .variables_found(&self.variables_found)
            .variables_not_found(&self.variables_not_found);

        debug!("Processing check: {:#?}", safe_data);

        let maybe_secret_data = safe_data
            .clone()
            .secret_command(self.secret_command_or_command());

        let cmd_vec = match shellwords::split(self.secret_command_or_command()) {
            Ok(v) => v,
            Err(_) => {
                error!("Failed to split the command. Bailing.");
                return maybe_secret_data
                    .status(3)
                    .short_output("UNKNOWN: Command split error")
                    .build();
            }
        };

        if cmd_vec.is_empty() {
            error!("After splitting the command by words, the command is empty. Bailing.");
            return maybe_secret_data
                .status(3)
                .short_output("UNKNOWN: Empty command")
                .build();
        }

        let cmd = &cmd_vec[0];
        let args = &cmd_vec[1..];

        let secs = Duration::from_secs(self.timeout);
        let start_time = Instant::now();

        // stderr is never shown, so it is discarded rather than piped: a pipe nobody reads
        // blocks the plugin once its buffer fills.
        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // A process group of its own lets a timeout stop everything the plugin started.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                debug!("Failed to spawn command: {}'", e);
                return maybe_secret_data
                    .status(3)
                    .parse_output(&format!("Failed to execute command with error: '{}'", e))
                    .with_execution_time(start_time.elapsed())
                    .build();
            }
        };

        // Read stdout while the plugin runs, so output larger than the pipe buffer cannot
        // block it. The reader is not waited for past the timeout: a background process
        // that inherited stdout may hold the pipe open long after the plugin has exited.
        let captured = Arc::new(Mutex::new(Vec::new()));
        let (done_tx, done_rx) = mpsc::channel();
        if let Some(mut stdout) = child.stdout.take() {
            let captured = Arc::clone(&captured);
            thread::spawn(move || {
                let _ = done_tx.send(read_capped(&mut stdout, &captured, MAX_OUTPUT_BYTES));
            });
        }

        let timeout_result = |execution_time: Duration| {
            let timeout_msg = match secs.as_secs() {
                1 => TimeoutMessage::Single,
                _ => TimeoutMessage::Multi(secs.as_secs()),
            };
            maybe_secret_data
                .clone()
                .status(3)
                .short_output(&timeout_msg.to_string())
                .with_execution_time(execution_time)
                .build()
        };

        // A failure to wait on or kill the process reports UNKNOWN (3) for this check instead
        // of aborting the whole batch.
        let mut status_code = 3;
        let mut output = String::new();
        let execution_time = match child.wait_timeout(secs) {
            Ok(Some(status)) => {
                let execution_time = start_time.elapsed();
                // A plugin that exits just before its timeout still gets a moment for the
                // reader to collect what it wrote.
                let remaining = secs
                    .saturating_sub(execution_time)
                    .max(Duration::from_millis(100));
                let read_result = match done_rx.recv_timeout(remaining) {
                    Ok(Ok(truncated)) => {
                        if truncated {
                            warn!(
                                "Output of check '{}' exceeded {} bytes and was truncated",
                                self.name, MAX_OUTPUT_BYTES
                            );
                        }
                        Ok(())
                    }
                    Ok(Err(e)) => Err(e),
                    Err(RecvTimeoutError::Timeout) => {
                        debug!(
                            "A process started by check '{}' still holds its output open; using the output read so far",
                            self.name
                        );
                        Ok(())
                    }
                    Err(RecvTimeoutError::Disconnected) => Ok(()),
                };
                match read_result {
                    Ok(()) => {
                        if let Some(code) = status.code() {
                            status_code = code;
                            let buffer = captured.lock().unwrap_or_else(|e| e.into_inner());
                            output = String::from_utf8_lossy(&buffer).into_owned();
                        }
                    }
                    Err(e) => {
                        error!("Failed to read the output of the child process: {}", e);
                        output = format!("UNKNOWN: Process read error: {}", e);
                    }
                }
                execution_time
            }
            Ok(None) => {
                // Never wait() here: it would block for as long as a plugin that survived
                // the kill keeps running.
                if let Err(e) = kill_process_group(&mut child) {
                    error!("Failed to kill timed out child process: {}", e);
                }
                let _ = child.try_wait();
                return timeout_result(start_time.elapsed());
            }
            Err(e) => {
                error!("Failed to wait on child process: {}", e);
                output = format!("UNKNOWN: Process wait error: {}", e);
                start_time.elapsed()
            }
        };

        // Build the check result based on the output and the status code
        maybe_secret_data
            .status(status_code)
            .parse_output(&output)
            .with_execution_time(execution_time)
            .build()
    }
}

impl Default for CheckBuilder {
    fn default() -> Self {
        CheckBuilder {
            name: None,
            command: None,
            secret_command: None,
            timeout: Some(5),
            variables_found: None,
            variables_not_found: None,
        }
    }
}

impl CheckBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn command(mut self, command: &str) -> Self {
        self.command = Some(command.to_string());
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_variables(mut self) -> Result<Self, VariableError> {
        if let Some(name) = &self.name {
            let variable_string = VariableString::from_str(name)?;
            if let Some(obfuscated_string) = variable_string.obfuscated_string {
                self.name = Some(obfuscated_string);
            } else {
                self.name = variable_string.clear_string();
            }
        }

        if let Some(command) = &self.command {
            let new_command = VariableString::from_str(command)?;
            self.command = match new_command.obfuscated_string {
                Some(ref obfuscated_string) => Some(obfuscated_string.to_string()),
                None => new_command.clear_string(),
            };
            self.secret_command = match new_command.obfuscated_string {
                Some(ref _obfuscated_string) => new_command.clear_string(),
                None => None,
            };
            self.variables_found = new_command.variables_found;
            self.variables_not_found = new_command.variables_not_found;
        }

        Ok(self)
    }

    pub fn build_raw(self) -> Check {
        Check {
            name: self.name.unwrap_or_default(),
            command: self.command.unwrap_or_default(),
            secret_command: self.secret_command,
            timeout: self.timeout.unwrap_or_default(),
            variables_found: None,
            variables_not_found: None,
        }
    }

    pub fn build(mut self) -> Result<Check, VariableError> {
        self = self.with_variables()?;
        Ok(Check {
            name: self.name.unwrap_or_default(),
            command: self.command.unwrap_or_default(),
            secret_command: self.secret_command,
            timeout: self.timeout.unwrap_or_default(),
            variables_found: self.variables_found,
            variables_not_found: self.variables_not_found,
        })
    }
}

impl ChecksExt for Checks {
    fn total_time_from_timeouts(&self) -> Duration {
        self.iter()
            .map(|check| check.timeout)
            .map(Duration::from_secs)
            .sum()
    }
}

fn expand_checks_from_single_range(check: &Check, range: &Range) -> Checks {
    let mut checks = Checks::new();
    for i in range.start..=range.end {
        let name = check.name.replace(
            &format!("!!{}:{}..{}!!", range.name, range.start, range.end),
            &i.to_string(),
        );
        let command = check.command.replace(
            &format!("!!{}:{}..{}!!", range.name, range.start, range.end),
            &i.to_string(),
        );
        let secret_command: Option<String> = check.secret_command.as_ref().map(|cmd| {
            cmd.replace(
                &format!("!!{}:{}..{}!!", range.name, range.start, range.end),
                &i.to_string(),
            )
        });
        checks.push(Check::new(&name, &command, secret_command, check.timeout));
    }
    checks
}

fn expand_checks_from_double_range(check: &Check, range1: &Range, range2: &Range) -> Checks {
    let mut checks = Checks::new();
    for i in range1.start..=range1.end {
        for j in range2.start..=range2.end {
            let name = check.name.replace(
                &format!("!!{}:{}..{}!!", range1.name, range1.start, range1.end),
                &i.to_string(),
            );
            let name = name.replace(
                &format!("!!{}:{}..{}!!", range2.name, range2.start, range2.end),
                &j.to_string(),
            );

            let command = check.command.replace(
                &format!("!!{}:{}..{}!!", range1.name, range1.start, range1.end),
                &i.to_string(),
            );
            let command = command.replace(
                &format!("!!{}:{}..{}!!", range2.name, range2.start, range2.end),
                &j.to_string(),
            );

            let secret_command = match &check.secret_command {
                Some(cmd) => {
                    let new_cmd = cmd.replace(
                        &format!("!!{}:{}..{}!!", range1.name, range1.start, range1.end),
                        &i.to_string(),
                    );
                    let new_cmd = new_cmd.replace(
                        &format!("!!{}:{}..{}!!", range2.name, range2.start, range2.end),
                        &j.to_string(),
                    );
                    Some(new_cmd)
                }
                None => None,
            };

            checks.push(Check::new(&name, &command, secret_command, check.timeout));
        }
    }
    checks
}

pub async fn run_all_checks_in_parallel(
    checks: Checks,
) -> Result<CheckResults, Box<dyn std::error::Error>> {
    let futures = checks
        .into_iter()
        .map(|check| tokio::task::spawn_blocking(move || check.run()));
    let results = futures::future::join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CheckResults(results))
}

pub fn run_all_checks_sequentially(
    checks: Checks,
) -> Result<CheckResults, Box<dyn std::error::Error>> {
    let results = checks.into_iter().map(|check| check.run()).collect();
    Ok(CheckResults(results))
}

#[cfg(test)]
mod check_test {
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_existing_var_in_command_name() -> Result<(), Box<dyn std::error::Error>> {
        std::env::set_var("FOO", "bar");
        std::env::set_var("BAZ", "qux");

        let check = CheckBuilder::new()
            .name("test $FOO$")
            .command("echo $FOO$")
            .build()?;

        assert_eq!(check.name, "test bar");
        assert_eq!(check.command, "echo bar");

        Ok(())
    }

    #[test]
    fn test_missing_var_in_command_name() -> Result<(), Box<dyn std::error::Error>> {
        let check = CheckBuilder::new()
            .name("test $MISSING_ENV_VAR$")
            .command("echo $MISSING_ENV_VAR$")
            .build()?;

        assert_eq!(check.name, "test $MISSING_ENV_VAR$");
        assert_eq!(check.command, "echo $MISSING_ENV_VAR$");

        Ok(())
    }

    #[test]
    fn test_check_builder_with_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let check = CheckBuilder::new()
            .name("test")
            .command("echo test")
            .timeout(30)
            .build()?;

        assert_eq!(check.timeout, 30);
        Ok(())
    }

    #[test]
    fn test_expand_ranges_no_range() {
        let check = Check::new("simple", "echo hello", None, 5);
        let expanded = check.expand_ranges();
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].name(), "simple");
    }

    #[test]
    fn test_expand_ranges_single() {
        let check = Check::new("test_!!A:1..3!!", "echo !!A:1..3!!", None, 5);
        let expanded = check.expand_ranges();
        assert_eq!(expanded.len(), 3);
        assert_eq!(expanded[0].name(), "test_1");
        assert_eq!(expanded[1].name(), "test_2");
        assert_eq!(expanded[2].name(), "test_3");
        assert_eq!(expanded[0].secret_command_or_command(), "echo 1");
        assert_eq!(expanded[1].secret_command_or_command(), "echo 2");
        assert_eq!(expanded[2].secret_command_or_command(), "echo 3");
    }

    #[test]
    fn test_expand_ranges_double() {
        let check = Check::new(
            "test_!!A:1..2!!_!!B:3..4!!",
            "echo !!A:1..2!! !!B:3..4!!",
            None,
            5,
        );
        let expanded = check.expand_ranges();
        assert_eq!(expanded.len(), 4);
        assert_eq!(expanded[0].name(), "test_1_3");
        assert_eq!(expanded[1].name(), "test_1_4");
        assert_eq!(expanded[2].name(), "test_2_3");
        assert_eq!(expanded[3].name(), "test_2_4");
    }

    #[test]
    #[should_panic(expected = "Ranges in name and command do not match")]
    fn test_expand_ranges_mismatched_panics() {
        let check = Check::new("test_!!A:1..3!!", "echo !!B:1..3!!", None, 5);
        let _ = check.expand_ranges();
    }

    #[test]
    fn test_expand_ranges_preserves_secret_command() {
        let check = Check::new(
            "test_!!A:1..2!!",
            "echo !!A:1..2!!",
            Some("secret !!A:1..2!!".to_string()),
            5,
        );
        let expanded = check.expand_ranges();
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].secret_command(), Some("secret 1".to_string()));
        assert_eq!(expanded[1].secret_command(), Some("secret 2".to_string()));
    }

    #[test]
    fn test_total_time_from_timeouts() {
        let checks = vec![
            Check::new("a", "echo a", None, 5),
            Check::new("b", "echo b", None, 10),
            Check::new("c", "echo c", None, 3),
        ];
        assert_eq!(
            checks.total_time_from_timeouts(),
            std::time::Duration::from_secs(18)
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_run_all_checks_sequentially() -> Result<(), Box<dyn std::error::Error>> {
        let checks = vec![
            CheckBuilder::new()
                .name("Seq check 1")
                .command("echo seq_hello")
                .build()?,
            CheckBuilder::new()
                .name("Seq check 2")
                .command("echo seq_world")
                .build()?,
        ];

        let results = run_all_checks_sequentially(checks)?;
        assert_eq!(results.0.len(), 2);
        assert_eq!(results.0[0].short_output().trim(), "seq_hello");
        assert_eq!(results.0[1].short_output().trim(), "seq_world");
        Ok(())
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_run_command_not_found() {
        let check = Check::new("Not Found", "/nonexistent/binary/foobar", None, 5);
        let result = check.run();
        // The process should return UNKNOWN (3) for a non-existent command, not crash
        assert_eq!(result.status(), Some(3));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_run_reports_exit_code_and_ignores_stderr() {
        let check = Check::new("Stderr", "sh -c 'echo oops >&2; echo out; exit 2'", None, 5);
        let result = check.run();
        assert_eq!(result.status(), Some(2));
        assert_eq!(result.short_output(), "out");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_run_empty_output() {
        let check = Check::new("Empty", "true", None, 5);
        let result = check.run();
        assert_eq!(result.status(), Some(0));
        assert_eq!(result.short_output(), "");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_run_with_exit_code_1() {
        let check = Check::new("Warning", "sh -c 'echo WARNING && exit 1'", None, 5);
        let result = check.run();
        assert_eq!(result.status(), Some(1));
        assert_eq!(result.short_output(), "WARNING");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_run_with_perfdata_output() {
        let check = Check::new(
            "Perf Check",
            "echo 'OK - all good|metric=42%;80;90;0;100'",
            None,
            5,
        );
        let result = check.run();
        assert_eq!(result.status(), Some(0));
        assert_eq!(result.short_output(), "OK - all good");
        assert_eq!(result.performance_data(), "metric=42%;80;90;0;100");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_run_with_output_larger_than_pipe_buffer() {
        // About 90 KB on stdout and on stderr, more than a pipe buffer holds.
        for command in [
            "sh -c 'yes ok | head -n 30000'",
            "sh -c 'yes err | head -n 30000 >&2; echo ok'",
        ] {
            let result = Check::new("Big", command, None, 5).run();
            assert_eq!(result.status(), Some(0), "{command}");
            assert_eq!(result.short_output(), "ok", "{command}");
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_timeout_is_not_extended_by_child_processes() {
        // The background sleep inherits stdout and keeps it open after the shell is killed.
        let started = std::time::Instant::now();
        let result = Check::new("Lingering", "sh -c 'sleep 5 & sleep 5'", None, 1).run();
        assert_eq!(result.status(), Some(3));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_timeout_kills_processes_started_by_the_plugin() {
        // Each subshell would write its marker after the timeout, unless it is killed too.
        // Several checks time out at once, as in a template run.
        let dir = tempfile::tempdir().unwrap();
        let markers: Vec<_> = (0..4).map(|i| dir.path().join(format!("m{i}"))).collect();
        let handles: Vec<_> = markers
            .iter()
            .map(|marker| {
                let command = format!("sh -c '(sleep 2; touch {}) & sleep 10'", marker.display());
                std::thread::spawn(move || Check::new("Group", &command, None, 1).run())
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap().status(), Some(3));
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
        for marker in &markers {
            assert!(
                !marker.exists(),
                "a process started by the plugin survived the timeout"
            );
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_result_is_kept_when_a_child_process_holds_stdout() {
        // The shell exits at once, but the background sleep keeps stdout open.
        let started = std::time::Instant::now();
        let result = Check::new("Detached", "sh -c 'sleep 5 & echo ok'", None, 1).run();
        assert_eq!(result.status(), Some(0));
        assert_eq!(result.short_output(), "ok");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_check_output_is_capped_and_the_rest_drained() {
        // One line twice the cap. The plugin can only exit 0 if all of it is read.
        let command = format!(
            "sh -c 'head -c {} /dev/zero | tr \\\\0 a'",
            2 * MAX_OUTPUT_BYTES
        );
        let result = Check::new("Flood", &command, None, 10).run();
        assert_eq!(result.status(), Some(0));
        assert_eq!(result.short_output().len(), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn test_secret_command_or_command_returns_command_when_no_secret() {
        let check = Check::new("test", "echo hello", None, 5);
        assert_eq!(check.secret_command_or_command(), "echo hello");
    }

    #[test]
    fn test_secret_command_or_command_returns_secret_when_present() {
        let check = Check::new("test", "echo ***", Some("echo secret".to_string()), 5);
        assert_eq!(check.secret_command_or_command(), "echo secret");
    }
}
