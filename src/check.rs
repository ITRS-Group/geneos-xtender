use crate::result::{CheckResult, CheckResultBuilder, CheckResults};
use log::debug;
use serde::{Deserialize, Serialize};
use shellwords;
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;
use wait_timeout::ChildExt;

const RANGE_RE: &str = r"!!(A|B):([0-9]+)\.\.([0-9]+)!!";
const VARIABLE_RE: &str = r"\$([A-Z_0-9]+)\$";

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

pub type VariableName = String;
pub type VariableValue = Option<String>;

pub type Variables = Vec<VariableKind>;
pub trait VariablesExt {
    fn to_string(&self) -> String;
}

impl VariablesExt for Variables {
    fn to_string(&self) -> String {
        let strings = self
            .iter()
            .map(|v| match v {
                VariableKind::Public(v) => v.to_public_string(),
                VariableKind::Secret(v) => v.to_secret_string(),
            })
            .collect::<Vec<String>>();

        if strings.is_empty() {
            return String::new();
        }

        strings.join(",")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum Variable {
    Found(VariableName, VariableValue),
    NotFound(VariableName),
}

#[derive(Debug)]
pub struct VariableLookupError;

impl Error for VariableLookupError {}

impl Display for VariableLookupError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to lookup Variable")
    }
}

impl FromStr for Variable {
    type Err = VariableLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = std::env::var(s);
        if let Ok(value) = value {
            Ok(Self::Found(s.to_string(), Some(value)))
        } else {
            Ok(Self::NotFound(s.to_string()))
        }
    }
}

impl Variable {
    pub fn to_public_string(&self) -> String {
        match self {
            Variable::Found(name, value) => format!("{}=\"{}\"", name, value.as_ref().unwrap()),
            Variable::NotFound(name) => name.clone(),
        }
    }

    pub fn to_secret_string(&self) -> String {
        match self {
            Variable::Found(name, _) => format!("{}=***", name),
            Variable::NotFound(name) => name.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum VariableKind {
    Public(Variable),
    Secret(Variable),
}

#[derive(Debug, Default)]
pub struct VariableString {
    pub original_string: String,
    pub new_string: Option<String>,
    pub variables_found: Option<Variables>,
    pub variables_not_found: Option<Variables>,
}

#[derive(Debug)]
pub enum VariableStringParseError {
    RegexError,
    VariableError(Box<dyn Error>),
}

impl Error for VariableStringParseError {}

impl Display for VariableStringParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VariableStringParseError::RegexError => {
                write!(f, "Failed to compile VariableString Regex")
            }
            VariableStringParseError::VariableError(err) => write!(f, "Variable error: {}", err),
        }
    }
}

impl From<regex::Error> for VariableStringParseError {
    fn from(_: regex::Error) -> Self {
        VariableStringParseError::RegexError
    }
}

impl From<VariableLookupError> for VariableStringParseError {
    fn from(err: VariableLookupError) -> Self {
        VariableStringParseError::VariableError(Box::new(err))
    }
}

impl FromStr for VariableString {
    type Err = VariableStringParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let variable_re = regex::Regex::new(VARIABLE_RE)?;
        let variable_names = variable_re
            .captures_iter(s)
            .map(|c| c.get(1).unwrap().as_str().to_string())
            .collect::<Vec<VariableName>>();

        let mut new_string = s.to_string();

        let mut found_variables = Variables::new();
        let mut missing_variables = Variables::new();

        if !variable_names.is_empty() {
            for variable_name in &variable_names {
                let variable = Variable::from_str(variable_name)?;

                match variable {
                    Variable::Found(name, value)
                        if value.as_ref().is_some_and(|x| x.starts_with("+encs+")) =>
                    // TODO: Is this what I want to do or do I want to replace the value with ***?
                    {
                        new_string =
                            new_string.replace(&format!("${}$", name), value.as_ref().unwrap());
                        found_variables.push(VariableKind::Secret(Variable::Found(
                            name.to_string(),
                            value,
                        )));
                    }
                    Variable::Found(name, value) => {
                        new_string =
                            new_string.replace(&format!("${}$", name), value.as_ref().unwrap());
                        found_variables.push(VariableKind::Public(Variable::Found(
                            name.to_string(),
                            value,
                        )));
                    }
                    Variable::NotFound(name) => {
                        missing_variables
                            .push(VariableKind::Public(Variable::NotFound(name.to_string())));
                    }
                }
            }

            found_variables.sort();
            found_variables.dedup();

            missing_variables.sort();
            missing_variables.dedup();
        }

        Ok(Self {
            original_string: s.to_string(),
            new_string: Some(new_string),
            variables_found: {
                if !found_variables.is_empty() {
                    Some(found_variables)
                } else {
                    None
                }
            },
            variables_not_found: {
                if !missing_variables.is_empty() {
                    Some(missing_variables)
                } else {
                    None
                }
            },
        })
    }
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

        assert_eq!(
            &VariableString::from_str("hello")
                .unwrap()
                .new_string
                .unwrap(),
            "hello"
        );
        assert_eq!(
            &VariableString::from_str("hello FOO$")
                .unwrap()
                .new_string
                .unwrap(),
            "hello FOO$"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO")
                .unwrap()
                .new_string
                .unwrap(),
            "hello $FOO"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO$")
                .unwrap()
                .new_string
                .unwrap(),
            "hello bar"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO$ $BAZ$")
                .unwrap()
                .new_string
                .unwrap(),
            "hello bar qux"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO$ $BAZ$ $FOO$")
                .unwrap()
                .new_string
                .unwrap(),
            "hello bar qux bar"
        );
    }

    #[test]
    fn test_replace_variables_in_str_missing_var() {
        std::env::set_var("FOO", "bar");
        std::env::set_var("BAZ", "qux");

        let r = VariableString::from_str("hello $FOO$ $MISSING$ $BAZ$");

        assert_eq!("hello bar $MISSING$ qux", r.unwrap().new_string.unwrap());
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
