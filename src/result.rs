use regex::Regex;
use serde::Serialize;
use std::str::FromStr;

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    name: String,
    command: String,
    status: Option<i32>,
    short_output: String,
    long_output: String,
    performance_data: String,
}

#[derive(Debug, Default)]
pub struct CheckResultBuilder {
    name: Option<String>,
    command: Option<String>,
    status: Option<i32>,
    short_output: Option<String>,
    long_output: Option<String>,
    performance_data: Option<String>,
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

    pub fn parse_output(mut self, output: &str) -> Self {
        self.short_output = Some(extract_short_output(output));
        self.long_output = Some(extract_long_output(output));
        self.performance_data = Some(extract_performance_data(output));
        self
    }

    pub fn build(self) -> CheckResult {
        CheckResult {
            name: escape_chars(&self.name.unwrap_or_default()),
            command: escape_chars(&self.command.unwrap_or_default()),
            status: self.status,
            short_output: escape_chars(&self.short_output.unwrap_or_default()),
            long_output: escape_chars(&self.long_output.unwrap_or_default()),
            performance_data: self.performance_data.unwrap_or_default(),
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
    fn add_performance_data(mut self, perf: &str) -> Self {
        self.label = label(perf);
        self.value = value(perf);
        self.uom = uom(perf);
        self.warn = warn(perf);
        self.crit = crit(perf);
        self.min = min(perf);
        self.max = max(perf);
        self
    }

    fn status_from_perfdata(mut self) -> Self {
        if self.status.is_some() {
            return self;
        }

        if self.value.is_none() {
            return self;
        }

        if let Some(c) = self.crit.as_ref() {
            if perfdata::ThresholdRange::from_str(c.as_str())
                .unwrap()
                .is_alert(self.value.unwrap())
            {
                self.status = Some(2);
                return self;
            }
        }

        if let Some(w) = self.warn.as_ref() {
            if perfdata::ThresholdRange::from_str(w.as_str())
                .unwrap()
                .is_alert(self.value.unwrap())
            {
                self.status = Some(1);
                return self;
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
            ..ProcessedCheckResult::default()
        }
    }

    pub fn secondary_entry_from_check_result(check_result: &CheckResult, label: &str) -> Self {
        Self {
            name: format!("\t{}#{}", check_result.name(), label),
            ..ProcessedCheckResult::default()
        }
    }
}

impl ProcessedCheckResultsExt for ProcessedCheckResults {
    fn from_check_result(check_result: &CheckResult) -> Self {
        let perf_binding = check_result.performance_data();
        let perf_metrics: Vec<String> = shellwords::split(&perf_binding).unwrap();
        let perf_count = perf_metrics.len();
        let mut results = ProcessedCheckResults::with_capacity(perf_count + 1);

        if perf_count < 2 {
            let mut c = ProcessedCheckResult::main_entry_from_check_result(check_result);
            if perf_count == 1 {
                c = c.add_performance_data(&perf_metrics[0]);
                c = c.status_from_perfdata();
            }
            results.push(c);
            return results;
        } else {
            for (i, p) in perf_metrics.iter().enumerate() {
                if i == 0 {
                    let c1 = ProcessedCheckResult::main_entry_from_check_result(check_result);
                    let mut c2 = ProcessedCheckResult::secondary_entry_from_check_result(
                        check_result,
                        &label(p).unwrap_or_default(),
                    );
                    c2 = c2.add_performance_data(p);
                    c2 = c2.status_from_perfdata();
                    results.push(c1);
                    results.push(c2);
                } else {
                    let mut c = ProcessedCheckResult::secondary_entry_from_check_result(
                        check_result,
                        &label(p).unwrap_or_default(),
                    );
                    c = c.add_performance_data(p);
                    c = c.status_from_perfdata();
                    results.push(c);
                }
            }
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
    Regex::new("([^=]+)=([^=]+)")
        .unwrap()
        .captures(perf)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim_matches('\'').to_string())
}

fn value(perf: &str) -> Option<f64> {
    Regex::new("([^=;]+)=?([0-9.]+)")
        .unwrap()
        .captures(perf)
        .and_then(|cap| cap.get(2))
        .and_then(|m| f64::from_str(m.as_str()).ok())
}

fn uom(perf: &str) -> Option<String> {
    Regex::new("([0-9'=]+)([^0-9'=; ]+)([ ;]|$)")
        .unwrap()
        .captures(perf)
        .and_then(|cap| cap.get(2))
        .map(|m| m.as_str().to_string())
}

fn warn(perf: &str) -> Option<String> {
    Regex::new("([^;]*;)([^;]+)(.*)")
        .unwrap()
        .captures(perf)
        .and_then(|cap| cap.get(2))
        .map(|m| m.as_str().to_string())
}

fn crit(perf: &str) -> Option<String> {
    Regex::new("([^;]*;)([^;]+;)([^;]+)(.*)")
        .unwrap()
        .captures(perf)
        .and_then(|cap| cap.get(3))
        .map(|m| m.as_str().to_string())
}

fn min(perf: &str) -> Option<String> {
    Regex::new("([^;]*;)([^;]+;)([^;]+;)([^;]+)(.*)")
        .unwrap()
        .captures(perf)
        .and_then(|cap| cap.get(4))
        .map(|m| m.as_str().to_string())
}

fn max(perf: &str) -> Option<String> {
    Regex::new("([^;]*;)([^;]+;)([^;]+;)([^;]+;)([^;]+)(.*)")
        .unwrap()
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

fn extract_performance_data(output: &str) -> String {
    output
        .find('|')
        .map_or_else(String::new, |i| output[i + 1..].trim().to_string())
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
