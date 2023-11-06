use crate::range::{Range, Ranges, RangesExt};
use crate::result::{CheckResult, CheckResultBuilder, CheckResults};
use crate::variable::{VariableString, Variables};
use log::debug;
use serde::{Deserialize, Serialize};
use shellwords;
use std::fmt;
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;
use wait_timeout::ChildExt;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Check {
    pub name: String,
    pub command: String,
    pub timeout: u64,
    #[serde(skip)]
    pub variables_found: Option<Variables>,
    #[serde(skip)]
    pub variables_not_found: Option<Variables>,
}

#[derive(Debug)]
pub struct CheckBuilder {
    name: Option<String>,
    command: Option<String>,
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
            timeout: 5,
            variables_found: None,
            variables_not_found: None,
        }
    }
}

impl Check {
    pub fn new(name: &str, command: &str, timeout: u64) -> Self {
        Self {
            name: name.to_string(),
            command: command.to_string(),
            timeout,
            variables_found: None,
            variables_not_found: None,
        }
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(&self).unwrap()
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
        let data = CheckResultBuilder::new()
            .name(&self.name)
            .command(&self.command)
            .variables_found(&self.variables_found)
            .variables_not_found(&self.variables_not_found);

        debug!("Running check: {:#?}", data);

        let cmd_vec = match shellwords::split(&self.command) {
            Ok(v) => v,
            Err(e) => panic!(
                "Failed to split command: \'{}\' with error: \'{}\'",
                self.command, e
            ),
        };

        if cmd_vec.is_empty() {
            panic!(
                "After splitting the command by words, the command is empty. Original command: \'{}\'",
                self.command
            );
        }

        let cmd = &cmd_vec[0];
        let args = &cmd_vec[1..];

        debug!("Command: {}", cmd);
        debug!("Arguments: {:?}", args);
        debug!("Number of arguments: {}", args.len());
        debug!("Timeout: {}", self.timeout);

        let mut timed_out = false;
        let mut child = std::process::Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to execute command: \'{}\' with error: \'{}\'",
                    self.command, e
                )
            });

        let secs = std::time::Duration::from_secs(self.timeout);
        let start_time = std::time::Instant::now();
        let execution_time: std::time::Duration;
        let exit_code = match child
            .wait_timeout(secs)
            .unwrap_or_else(|_| panic!("Failed to wait for command: {}", self.command))
        {
            Some(status) => {
                execution_time = start_time.elapsed();
                status.code()
            }
            None => {
                timed_out = true;
                child.kill().unwrap();
                execution_time = start_time.elapsed();
                child.wait().unwrap().code()
            }
        };

        let timeout_msg = match self.timeout {
            1 => TimeoutMessage::Single.to_string(),
            n => TimeoutMessage::Multi(n).to_string(),
        };

        if timed_out {
            return data
                .status(3)
                .short_output(&timeout_msg)
                .with_execution_time(execution_time)
                .build();
        }

        let mut s = String::new();
        child
            .stdout
            .unwrap()
            .read_to_string(&mut s)
            .unwrap_or_else(|_| panic!("Failed to read stdout from command: {}", self.command));

        match exit_code {
            Some(c) => data
                .status(c)
                .parse_output(&s)
                .with_execution_time(execution_time)
                .build(),
            None => data
                .parse_output(&s)
                .with_execution_time(execution_time)
                .build(),
        }
    }
}

impl Default for CheckBuilder {
    fn default() -> Self {
        CheckBuilder {
            name: None,
            command: None,
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

    pub fn with_variables(mut self) -> Self {
        if let Some(name) = &self.name {
            self.name = VariableString::from_str(name).unwrap().new_string;
        }

        if let Some(command) = &self.command {
            let new_command = VariableString::from_str(command).unwrap();
            self.command = new_command.new_string;
            self.variables_found = new_command.variables_found;
            self.variables_not_found = new_command.variables_not_found;
        }

        self
    }

    pub fn build_raw(self) -> Check {
        Check {
            name: self.name.unwrap_or_default(),
            command: self.command.unwrap_or_default(),
            timeout: self.timeout.unwrap_or_default(),
            variables_found: None,
            variables_not_found: None,
        }
    }

    pub fn build(mut self) -> Check {
        self = self.with_variables();
        Check {
            name: self.name.unwrap_or_default(),
            command: self.command.unwrap_or_default(),
            timeout: self.timeout.unwrap_or_default(),
            variables_found: self.variables_found,
            variables_not_found: self.variables_not_found,
        }
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

        checks.push(Check::new(&name, &command, check.timeout));
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

            checks.push(Check::new(&name, &command, check.timeout));
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
    fn test_existing_var_in_command_name() {
        std::env::set_var("FOO", "bar");
        std::env::set_var("BAZ", "qux");

        let check = CheckBuilder::new()
            .name("test $FOO$")
            .command("echo $FOO$")
            .build();

        assert_eq!(check.name, "test bar");
        assert_eq!(check.command, "echo bar");
    }

    #[test]
    fn test_missing_var_in_command_name() {
        let check = CheckBuilder::new()
            .name("test $MISSING_ENV_VAR$")
            .command("echo $MISSING_ENV_VAR$")
            .build();

        assert_eq!(check.name, "test $MISSING_ENV_VAR$");
        assert_eq!(check.command, "echo $MISSING_ENV_VAR$");
    }
}
