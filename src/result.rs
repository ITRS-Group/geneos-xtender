use crate::variable::{Variables, VariablesExt};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::str::FromStr;

lazy_static! {
    static ref LABEL_RE: Regex = Regex::new("([^=]+)=([^=]+)").unwrap();
    static ref VALUE_RE: Regex = Regex::new("([^=;]+)=?([0-9.]+)").unwrap();
    static ref UOM_RE: Regex = Regex::new("([0-9'=]+)([^0-9'=; ]+)([ ;]|$)").unwrap();
    static ref WARN_RE: Regex = Regex::new("([^;]*;)([^;]+)(.*)").unwrap();
    static ref CRIT_RE: Regex = Regex::new("([^;]*;)([^;]+;)([^;]+)(.*)").unwrap();
    static ref MIN_RE: Regex = Regex::new("([^;]*;)([^;]+;)([^;]+;)([^;]+)(.*)").unwrap();
    static ref MAX_RE: Regex = Regex::new("([^;]*;)([^;]+;)([^;]+;)([^;]+;)([^;]+)(.*)").unwrap();
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    name: String,
    command: String,
    secret_command: String,
    status: Option<i32>,
    short_output: String,
    long_output: String,
    performance_data: String,
    execution_time: String,
    variables_found: Option<Variables>,
    variables_not_found: Option<Variables>,
}

#[derive(Clone, Debug, Default)]
pub struct CheckResultBuilder {
    name: Option<String>,
    command: Option<String>,
    secret_command: Option<String>,
    status: Option<i32>,
    short_output: Option<String>,
    long_output: Option<String>,
    performance_data: Option<String>,
    execution_time: Option<String>,
    variables_found: Option<Variables>,
    variables_not_found: Option<Variables>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessedCheckResult {
    name: String,
    status: Option<i32>,
    short_output: String,
    label: Option<String>,
    value: Option<f64>,
    uom: Option<String>,
    warn: Option<String>,
    crit: Option<String>,
    min: Option<String>,
    max: Option<String>,
    command: String,
    performance_data_string: String,
    long_output: String,
    execution_time: String,
    variables_found: Option<String>,
    variables_not_found: Option<String>,
}

pub struct CheckResults(pub Vec<CheckResult>);

pub type ProcessedCheckResults = Vec<ProcessedCheckResult>;

pub trait ProcessedCheckResultsExt {
    fn from_check_result(check_result: &CheckResult) -> Self;
    fn as_csv_string(&mut self) -> Result<String, Box<dyn std::error::Error>>;
}

impl CheckResult {
    pub fn name(&self) -> String {
        self.name.to_string()
    }

    pub fn command(&self) -> String {
        self.command.to_string()
    }

    pub fn status(&self) -> Option<i32> {
        self.status
    }

    pub fn short_output(&self) -> String {
        self.short_output.to_string()
    }

    pub fn long_output(&self) -> String {
        self.long_output.to_string()
    }

    pub fn performance_data(&self) -> String {
        self.performance_data.to_string()
    }

    pub fn execution_time(&self) -> String {
        self.execution_time.to_string()
    }

    pub fn variables_found(&self) -> Option<String> {
        match self.variables_found {
            Some(ref vars) if !vars.is_empty() => Some(escape_chars(&vars.to_string())),
            _ => None,
        }
    }

    pub fn variables_not_found(&self) -> Option<String> {
        match self.variables_not_found {
            Some(ref vars) if !vars.is_empty() => Some(escape_chars(&vars.to_string())),
            _ => None,
        }
    }
}

impl CheckResultBuilder {
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

    pub fn secret_command(mut self, secret_command: &str) -> Self {
        self.secret_command = Some(secret_command.to_string());
        self
    }

    pub fn status(mut self, status: i32) -> Self {
        self.status = Some(status);
        self
    }

    pub fn short_output(mut self, short_output: &str) -> Self {
        self.short_output = Some(short_output.to_string());
        self
    }

    pub fn long_output(mut self, long_output: &str) -> Self {
        self.long_output = Some(long_output.to_string());
        self
    }

    pub fn performance_data(mut self, performance_data: &str) -> Self {
        self.performance_data = Some(performance_data.to_string());
        self
    }

    pub fn variables_found(mut self, variables_found: &Option<Variables>) -> Self {
        self.variables_found = variables_found.clone();
        self
    }

    pub fn variables_not_found(mut self, variables_not_found: &Option<Variables>) -> Self {
        self.variables_not_found = variables_not_found.clone();
        self
    }

    pub fn parse_output(mut self, output: &str) -> Self {
        self.short_output = Some(extract_short_output(output));
        self.long_output = Some(extract_long_output(output));
        self.performance_data = Some(extract_performance_data(output).unwrap_or_default());
        self
    }

    pub fn with_execution_time(mut self, execution_time: std::time::Duration) -> Self {
        self.execution_time = Some(format!("{:.4} s", execution_time.as_secs_f64()));
        self
    }

    pub fn build(self) -> CheckResult {
        CheckResult {
            name: escape_chars(&self.name.unwrap_or_default()),
            command: escape_chars(&self.command.clone().unwrap_or_default()),
            secret_command: match &self.secret_command {
                Some(s) => escape_chars(s),
                None => self.command.unwrap_or_default(),
            },
            status: self.status,
            short_output: escape_chars(&self.short_output.unwrap_or_default()),
            long_output: escape_chars(&self.long_output.unwrap_or_default()),
            performance_data: self.performance_data.unwrap_or_default(),
            execution_time: self.execution_time.unwrap_or_default(),
            variables_found: self.variables_found,
            variables_not_found: self.variables_not_found,
        }
    }
}

impl CheckResults {
    pub fn process(&self) -> ProcessedCheckResults {
        let mut processed_results = ProcessedCheckResults::with_capacity(self.0.len());
        for r in self.0.iter() {
            processed_results.extend(ProcessedCheckResults::from_check_result(r));
        }
        processed_results
    }
}

impl ProcessedCheckResult {
    // Perfdata comes from the plugin, so each field is escaped like the other output
    // columns: a comma or line break in it must not add columns or rows to the CSV.
    fn add_performance_data(mut self, perf: &str) -> Self {
        let escaped = |field: Option<String>| field.map(|f| escape_chars(&f));
        self.label = escaped(label(perf));
        self.value = value(perf);
        self.uom = escaped(uom(perf));
        self.warn = escaped(warn(perf));
        self.crit = escaped(crit(perf));
        self.min = escaped(min(perf));
        self.max = escaped(max(perf));
        self
    }

    // A threshold that can't be parsed gives UNKNOWN (3) instead of letting the value pass as OK.
    fn status_from_perfdata(mut self) -> Self {
        if self.status.is_some() {
            return self;
        }

        let val = match self.value {
            Some(v) => v,
            None => return self,
        };

        if let Some(c) = self.crit.as_ref() {
            match perfdata::ThresholdRange::from_str(c.as_str()) {
                Ok(range) => {
                    if range.is_alert(val) {
                        self.status = Some(2);
                        return self;
                    }
                }
                Err(_) => {
                    self.status = Some(3);
                    return self;
                }
            }
        }

        if let Some(w) = self.warn.as_ref() {
            match perfdata::ThresholdRange::from_str(w.as_str()) {
                Ok(range) => {
                    if range.is_alert(val) {
                        self.status = Some(1);
                        return self;
                    }
                }
                Err(_) => {
                    self.status = Some(3);
                    return self;
                }
            }
        }

        self.status = Some(0);

        self
    }

    pub fn main_entry_from_check_result(check_result: &CheckResult) -> Self {
        Self {
            name: check_result.name(),
            command: check_result.command(),
            status: check_result.status(),
            short_output: check_result.short_output(),
            long_output: check_result.long_output(),
            performance_data_string: escape_chars(&check_result.performance_data()),
            execution_time: check_result.execution_time(),
            variables_found: check_result.variables_found(),
            variables_not_found: check_result.variables_not_found(),
            ..ProcessedCheckResult::default()
        }
    }

    pub fn secondary_entry_from_check_result(check_result: &CheckResult, label: &str) -> Self {
        Self {
            name: format!("\t{}#{}", check_result.name(), escape_chars(label)),
            ..ProcessedCheckResult::default()
        }
    }
}

impl ProcessedCheckResultsExt for ProcessedCheckResults {
    fn from_check_result(check_result: &CheckResult) -> Self {
        let perf_binding = check_result.performance_data();
        // Perfdata with unbalanced quotes falls back to splitting on whitespace.
        let perf_metrics: Vec<String> = shellwords::split(&perf_binding)
            .unwrap_or_else(|_| perf_binding.split_whitespace().map(String::from).collect());
        let perf_count = perf_metrics.len();
        let mut results = ProcessedCheckResults::with_capacity(perf_count + 1);

        // Special handling for 0 or 1 performance metric
        if perf_count < 2 {
            let mut c = ProcessedCheckResult::main_entry_from_check_result(check_result);
            if perf_count == 1 {
                c = c.add_performance_data(&perf_metrics[0]);
                c = c.status_from_perfdata();
            }
            results.push(c);
            return results;
        }

        // Handle 2+ performance metrics
        results.push(ProcessedCheckResult::main_entry_from_check_result(
            check_result,
        ));

        for p in &perf_metrics {
            let label = label(p).unwrap_or_default();
            let mut entry =
                ProcessedCheckResult::secondary_entry_from_check_result(check_result, &label);
            entry = entry.add_performance_data(p).status_from_perfdata();
            results.push(entry);
        }

        results
    }

    fn as_csv_string(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        // If there are no results, add an empty one to print the headers
        if self.is_empty() {
            self.push(ProcessedCheckResult::default());
        }
        let mut wtr = csv::WriterBuilder::new()
            .quote_style(csv::QuoteStyle::Never)
            .from_writer(vec![]);
        for r in self {
            wtr.serialize(r)?;
        }
        let data = String::from_utf8(wtr.into_inner()?)?;
        Ok(data)
    }
}

fn label(perf: &str) -> Option<String> {
    LABEL_RE
        .captures(perf)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim_matches('\'').to_string())
}

fn value(perf: &str) -> Option<f64> {
    VALUE_RE
        .captures(perf)
        .and_then(|cap| cap.get(2))
        .and_then(|m| f64::from_str(m.as_str()).ok())
}

fn uom(perf: &str) -> Option<String> {
    UOM_RE
        .captures(perf)
        .and_then(|cap| cap.get(2))
        .map(|m| m.as_str().to_string())
}

fn warn(perf: &str) -> Option<String> {
    WARN_RE
        .captures(perf)
        .and_then(|cap| cap.get(2))
        .map(|m| m.as_str().to_string())
}

fn crit(perf: &str) -> Option<String> {
    CRIT_RE
        .captures(perf)
        .and_then(|cap| cap.get(3))
        .map(|m| m.as_str().to_string())
}

fn min(perf: &str) -> Option<String> {
    MIN_RE
        .captures(perf)
        .and_then(|cap| cap.get(4))
        .map(|m| m.as_str().to_string())
}

fn max(perf: &str) -> Option<String> {
    MAX_RE
        .captures(perf)
        .and_then(|cap| cap.get(5))
        .map(|m| m.as_str().to_string())
}

fn escape_commas(s: &str) -> String {
    s.replace(',', "\\,")
}

fn escape_newlines(s: &str) -> String {
    s.replace('\n', "\\n")
}

fn escape_chars(s: &str) -> String {
    escape_newlines(&escape_commas(s))
}

fn extract_short_output(output: &str) -> String {
    let lines = output.lines().collect::<Vec<&str>>();
    let first_line = lines.first().unwrap_or(&"");

    if first_line.contains('|') {
        first_line
            .split('|')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        first_line.trim().to_string()
    }
}

// Admittedly a simplified version which doesn't handle multi-line performance data mixed with the
// output.
fn extract_long_output(output: &str) -> String {
    output
        .lines()
        .skip(1)
        .collect::<Vec<&str>>()
        .join("\n")
        .trim()
        .to_string()
}

fn extract_performance_data(output: &str) -> Option<String> {
    if output.contains("Usage: check")
        || output.contains("[-h|--help]")
        || output.contains("usage: check")
    {
        None
    } else {
        output.find('|').map(|i| output[i + 1..].trim().to_string())
    }
}

#[cfg(test)]
mod util_test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_perf_label() {
        assert_eq!(label("label=foo"), Some("label".to_string()));
        assert_eq!(label("'split label'=foo"), Some("split label".to_string()));
        assert_eq!(label("'Load Average'=1"), Some("Load Average".to_string()));
    }

    #[test]
    fn test_perf_value() {
        assert_eq!(value("label=42"), Some(42.0));
        assert_eq!(value("label=0.05%;70;90;;"), Some(0.05));
        assert_eq!(value("rta=0.222ms;100;500;0;"), Some(0.222));
        assert_eq!(value(""), None);
    }

    #[test]
    fn test_perf_uom() {
        assert_eq!(uom("label=0.05%;70;90;;"), Some("%".to_string()));
        assert_eq!(uom("rta=0.222ms;100;500;0;"), Some("ms".to_string()));
        assert_eq!(uom("label=42;10;20;;"), None);
        assert_eq!(uom("label=42"), None);
    }

    #[test]
    fn test_perf_warn() {
        assert_eq!(warn("label=0.05%;70;90;;"), Some("70".to_string()));
        assert_eq!(warn("label=42;10;20;0;100"), Some("10".to_string()));
        assert_eq!(warn("label=42"), None);
    }

    #[test]
    fn test_perf_crit() {
        assert_eq!(crit("label=0.05%;70;90;;"), Some("90".to_string()));
        assert_eq!(crit("label=42;10;20;0;100"), Some("20".to_string()));
        assert_eq!(crit("label=42"), None);
        assert_eq!(crit("label=42;10"), None);
    }

    #[test]
    fn test_perf_min() {
        assert_eq!(min("label=42;10;20;0;100"), Some("0".to_string()));
        assert_eq!(min("label=42;10;20;;"), None);
        assert_eq!(min("label=42"), None);
    }

    #[test]
    fn test_perf_max() {
        assert_eq!(max("label=42;10;20;0;100"), Some("100".to_string()));
        assert_eq!(max("label=42;10;20;0;"), None);
        assert_eq!(max("label=42"), None);
    }

    #[test]
    fn test_extract_performance_data() {
        assert_eq!(
            extract_performance_data("OK - all good|rta=0.1ms;100;500;0;"),
            Some("rta=0.1ms;100;500;0;".to_string())
        );
        assert_eq!(extract_performance_data("OK - no perfdata"), None);
        assert_eq!(extract_performance_data(""), None);
        // Usage output should not be treated as perfdata
        assert_eq!(
            extract_performance_data("Usage: check_http [-h|--help]"),
            None
        );
        assert_eq!(extract_performance_data("usage: check_foo -H host"), None);
    }

    #[test]
    fn test_escape_commas() {
        assert_eq!(escape_commas(""), "");
        assert_eq!(escape_commas("hello"), "hello");
        assert_eq!(escape_commas("hello,world"), "hello\\,world");
        assert_eq!(escape_commas("hello,world,"), "hello\\,world\\,");
    }

    #[test]
    fn test_escape_newlines() {
        assert_eq!(escape_newlines(""), "");
        assert_eq!(escape_newlines("hello"), "hello");
        assert_eq!(escape_newlines("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_newlines("hello\nworld\n"), "hello\\nworld\\n");
    }

    #[test]
    fn test_extract_short_output() {
        assert_eq!(extract_short_output(""), "");
        assert_eq!(extract_short_output("hello"), "hello");
        assert_eq!(extract_short_output("hello\nworld"), "hello");
        assert_eq!(extract_short_output("hello\nworld\n"), "hello");
        assert_eq!(extract_short_output("hello\nworld|foo=1\n"), "hello");
        assert_eq!(extract_short_output("hello\nworld|foo=1;;;\n"), "hello");
        assert_eq!(extract_short_output("hello\nworld\n|"), "hello");
        assert_eq!(extract_short_output("hello\nworld\n|foo"), "hello");
        assert_eq!(extract_short_output("hello\nworld\n|foo|bar"), "hello");
    }

    #[test]
    fn test_extract_long_output() {
        assert_eq!(extract_long_output(""), "");
        assert_eq!(extract_long_output("hello"), "");
        assert_eq!(extract_long_output("hello\nworld"), "world");
        assert_eq!(extract_long_output("hello\nworld\n"), "world");
        assert_eq!(extract_long_output("hello\nworld|foo=1\n"), "world|foo=1");
        assert_eq!(
            extract_long_output("hello\nworld|foo=1;;;\n"),
            "world|foo=1;;;"
        );
        assert_eq!(extract_long_output("hello\nworld\n|"), "world\n|");
        assert_eq!(extract_long_output("hello\nworld\n|foo"), "world\n|foo");
        assert_eq!(
            extract_long_output("hello\nworld\n|foo|bar"),
            "world\n|foo|bar"
        );
    }
}
