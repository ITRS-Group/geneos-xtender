use crate::result::{CheckResult, CheckResultBuilder, CheckResults};
use log::debug;
use shellwords;
use std::fmt;
use std::io::Read;
use std::time::Duration;
use wait_timeout::ChildExt;

const RANGE_RE: &str = r"!!(A|B):([0-9]+)\.\.([0-9]+)!!";
const VARIABLE_RE: &str = r"\$([A-Z_0-9]+)\$";

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Check {
    pub name: String,
    pub command: String,
    pub timeout: u64,
}

#[derive(Debug)]
pub struct CheckBuilder {
    name: Option<String>,
    command: Option<String>,
    timeout: Option<u64>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Range {
    pub name: String,
    pub start: i32,
    pub end: i32,
}

pub type Checks = Vec<Check>;
pub type Ranges = Vec<Range>;

pub trait ChecksExt {
    fn total_time_from_timeouts(&self) -> Duration;
}

pub enum TimeoutMessage {
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
        }
    }
}

impl Check {
    pub fn new(name: &str, command: &str, timeout: u64) -> Self {
        Self {
            name: name.to_string(),
            command: command.to_string(),
            timeout,
        }
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(&self).unwrap()
    }

    pub fn expand_ranges(self) -> Checks {
        let mut checks = Checks::new();

        let mut name_ranges = extract_ranges(&self.name);
        name_ranges.sort();
        name_ranges.dedup();

        let mut command_ranges = extract_ranges(&self.command);
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
            .command(&self.command);

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
        let exit_code = match child
            .wait_timeout(secs)
            .unwrap_or_else(|_| panic!("Failed to wait for command: {}", self.command))
        {
            Some(status) => status.code(),
            None => {
                timed_out = true;
                child.kill().unwrap();
                child.wait().unwrap().code()
            }
        };

        let timeout_msg = match self.timeout {
            1 => TimeoutMessage::Single.to_string(),
            n => TimeoutMessage::Multi(n).to_string(),
        };

        if timed_out {
            return data.status(3).short_output(&timeout_msg).build();
        }

        let mut s = String::new();
        child
            .stdout
            .unwrap()
            .read_to_string(&mut s)
            .unwrap_or_else(|_| panic!("Failed to read stdout from command: {}", self.command));

        match exit_code {
            Some(c) => data.status(c).parse_output(&s).build(),
            None => data.parse_output(&s).build(),
        }
    }
}

impl Default for CheckBuilder {
    fn default() -> Self {
        CheckBuilder {
            name: None,
            command: None,
            timeout: Some(5),
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
            let new_name = populate_variables_in_str(name);

            match new_name {
                Ok(s) => self.name = Some(s),
                Err(e) => {
                    panic!(
                        "Failed to populate variables in name of check: {}\n{}\n",
                        self.name.unwrap(),
                        e
                    );
                }
            }
        }
        if let Some(command) = &self.command {
            let new_command = populate_variables_in_str(command);

            match new_command {
                Ok(s) => self.command = Some(s),
                Err(e) => {
                    panic!(
                        "Failed to populate variables in command of check: {}\n{}\n",
                        self.command.unwrap(),
                        e
                    );
                }
            }
        }
        self
    }

    pub fn build_raw(self) -> Check {
        Check {
            name: self.name.unwrap_or_default(),
            command: self.command.unwrap_or_default(),
            timeout: self.timeout.unwrap_or_default(),
        }
    }

    pub fn build(mut self) -> Check {
        self = self.with_variables();
        Check {
            name: self.name.unwrap_or_default(),
            command: self.command.unwrap_or_default(),
            timeout: self.timeout.unwrap_or_default(),
        }
    }
}

impl Range {
    pub fn new(name: &str, start: i32, end: i32) -> Self {
        Self {
            name: name.to_string(),
            start,
            end,
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

fn populate_variables_in_str(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let variable_re = regex::Regex::new(VARIABLE_RE)?;
    let variables = variable_re
        .captures_iter(s)
        .map(|c| c.get(1).unwrap().as_str())
        .collect::<Vec<&str>>();

    if !variables.is_empty() {
        let mut s = s.to_string();
        let mut missing_variables = Vec::new();

        for variable in variables {
            let value = std::env::var(variable);

            if let Ok(value) = value {
                s = s.replace(&format!("${}$", variable), &value);
            } else {
                missing_variables.push(variable);
            }
        }

        if !missing_variables.is_empty() {
            return Err(format!(
                "Missing environment variables:\n{}",
                missing_variables.join("\n")
            )
            .into());
        }

        return Ok(s);
    }

    Ok(s.to_string())
}

pub fn contains_named_range(s: &str) -> bool {
    let range_re = regex::Regex::new(RANGE_RE).unwrap();
    range_re.is_match(s)
}

pub fn contains_multiple_ranges(s: &str) -> bool {
    let range_re = regex::Regex::new(RANGE_RE).unwrap();
    let mut ranges = Vec::new();

    for c in range_re.captures_iter(s) {
        let name = c.get(1).unwrap().as_str();
        let start = c.get(2).unwrap().as_str().parse::<i32>().unwrap();
        let end = c.get(3).unwrap().as_str().parse::<i32>().unwrap();
        ranges.push((name, start, end));
    }

    if ranges.is_empty() || ranges.len() == 1 {
        return false;
    }

    ranges.sort();
    ranges.dedup();

    ranges.len() > 1
}

fn extract_ranges(s: &str) -> Ranges {
    let range_re = regex::Regex::new(RANGE_RE).unwrap();
    let mut ranges = Ranges::new();

    for c in range_re.captures_iter(s) {
        let name = c.get(1).unwrap().as_str().to_string();
        let start = c.get(2).unwrap().as_str().parse::<i32>().unwrap();
        let end = c.get(3).unwrap().as_str().parse::<i32>().unwrap();
        ranges.push(Range::new(&name, start, end));
    }

    ranges
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

#[cfg(test)]
mod util_test {
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_replace_variables_in_str() {
        std::env::set_var("FOO", "bar");
        std::env::set_var("BAZ", "qux");

        assert_eq!(populate_variables_in_str("hello").unwrap(), "hello");
        assert_eq!(
            populate_variables_in_str("hello FOO$").unwrap(),
            "hello FOO$"
        );
        assert_eq!(
            populate_variables_in_str("hello $FOO").unwrap(),
            "hello $FOO"
        );
        assert_eq!(
            populate_variables_in_str("hello $FOO$").unwrap(),
            "hello bar"
        );
        assert_eq!(
            populate_variables_in_str("hello $FOO$ $BAZ$").unwrap(),
            "hello bar qux"
        );
        assert_eq!(
            populate_variables_in_str("hello $FOO$ $BAZ$ $FOO$").unwrap(),
            "hello bar qux bar"
        );
    }

    #[test]
    #[should_panic]
    fn test_replace_variables_in_str_missing_var() {
        std::env::set_var("FOO", "bar");
        std::env::set_var("BAZ", "qux");

        populate_variables_in_str("hello $FOO$ $MISSING$ $BAZ$").unwrap();
    }

    #[test]
    fn test_extract_ranges() {
        assert_eq!(extract_ranges(""), vec![]);
        assert_eq!(extract_ranges("!!A:1..2!!"), vec![Range::new("A", 1, 2)]);
        assert_eq!(extract_ranges("!!B:3..4!!"), vec![Range::new("B", 3, 4)]);
        assert_eq!(
            extract_ranges("!!A:1..2!! !!B:3..4!!"),
            vec![Range::new("A", 1, 2), Range::new("B", 3, 4)]
        );
        // Only A or B is allowed.
        assert_eq!(
            extract_ranges("!!A:1..2!! !!B:3..4!! !!C:5..6!!"),
            vec![Range::new("A", 1, 2), Range::new("B", 3, 4)]
        );
    }
}
