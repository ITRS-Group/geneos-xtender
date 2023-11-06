use crate::range::{Range, Ranges, RangesExt};
use crate::result::{CheckResult, CheckResultBuilder, CheckResults};
use crate::variable::{VariableError, VariableString, Variables};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use shellwords;
use std::fmt;
use std::io::Read;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

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

        let mut child = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let secs = Duration::from_secs(self.timeout);
        let start_time = Instant::now();
        let execution_time: Duration;
        let mut output = String::new();
        let mut status_code = 3;

        match child {
            Ok(ref mut child_proc) => {
                match child_proc.wait_timeout(secs).unwrap() {
                    Some(status) => {
                        execution_time = start_time.elapsed();
                        if let Some(code) = status.code() {
                            status_code = code;
                            child_proc
                                .stdout
                                .as_mut()
                                .unwrap()
                                .read_to_string(&mut output)
                                .unwrap();
                        }
                    }
                    None => {
                        child_proc.kill().unwrap();
                        execution_time = start_time.elapsed();
                        let timeout_msg = match secs.as_secs() {
                            1 => TimeoutMessage::Single,
                            _ => TimeoutMessage::Multi(secs.as_secs()),
                        };
                        let _kill_status = child_proc.wait().unwrap();
                        child_proc
                            .stderr
                            .as_mut()
                            .unwrap()
                            .read_to_string(&mut output)
                            .unwrap();
                        return maybe_secret_data
                            .status(3)
                            .short_output(&timeout_msg.to_string())
                            .with_execution_time(execution_time)
                            .build();
                    }
                };
            }
            Err(e) => {
                debug!("Failed to spawn command: {}'", e);
                execution_time = start_time.elapsed();
                status_code = 3;
                output = format!("Failed to execute command with error: '{}'", e);
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
}
